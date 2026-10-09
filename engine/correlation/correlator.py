"""Stateful event and alert correlation engine.

Correlates security events and alerts across sliding time windows to detect
multi-stage attacks, aggregate evidence, and manage incident lifecycles.
"""
from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from engine.detection.engine import DetectionEngine
from engine.models import (
    Alert,
    Event,
    EventType,
    Incident,
    IncidentStatus,
    MITREAttack,
    RiskScore,
    Severity,
    format_iso_utc,
)


class EventCorrelator:
    """Stateful correlator connecting alerts and events into cohesive Incidents."""

    def __init__(
        self,
        correlation_window_seconds: int = 180,
        ssh_compromise_window_seconds: int = 120,
    ) -> None:
        self.correlation_window_seconds = correlation_window_seconds
        self.ssh_compromise_window_seconds = ssh_compromise_window_seconds

        # Active incidents mapped by correlation key (e.g. source_ip)
        self._active_incidents: dict[str, Incident] = {}
        # Recent brute-force alert history: source_ip -> list of (timestamp, Alert)
        self._recent_bruteforce: dict[str, list[tuple[datetime, Alert]]] = defaultdict(list)
        # Completed / sealed incidents
        self._incidents: list[Incident] = []

    def process(self, event: Event, alerts: list[Alert]) -> list[Incident]:
        """Correlate an incoming event and any alerts it produced."""
        new_or_updated: list[Incident] = []
        src_ip = event.source_ip or "unknown"

        # 1. Track brute-force alerts
        for alert in alerts:
            if "brute" in alert.rule_name.lower() or alert.rule_id == "DET-SSH-001":
                self._recent_bruteforce[src_ip].append((alert.timestamp, alert))

        # 2. Check for SSH Brute Force -> Successful Login sequence (Compromise escalation)
        if (
            event.event_type == EventType.AUTHENTICATION_SUCCESS
            and event.service == "sshd"
            and src_ip in self._recent_bruteforce
        ):
            # Check if there was brute force within window
            cutoff = event.timestamp.timestamp() - self.ssh_compromise_window_seconds
            matching_bf = [
                (ts, alt)
                for ts, alt in self._recent_bruteforce[src_ip]
                if ts.timestamp() >= cutoff
            ]
            if matching_bf:
                incident = self._escalate_ssh_compromise(event, matching_bf[-1][1])
                new_or_updated.append(incident)
                return new_or_updated

        # 3. Standard incident aggregation for alerts
        for alert in alerts:
            incident = self._correlate_alert(alert, event)
            if incident not in new_or_updated:
                new_or_updated.append(incident)

        return new_or_updated

    def _correlate_alert(self, alert: Alert, event: Event) -> Incident:
        """Add an alert to an existing incident or create a new one."""
        key = alert.source_ip or alert.target_host or "generic"

        existing = self._active_incidents.get(key)
        if existing:
            # Check window
            time_diff = abs(alert.timestamp.timestamp() - existing.created_at.timestamp())
            if time_diff <= self.correlation_window_seconds:
                existing.add_alert(alert)
                # Escalate severity if incoming alert is higher
                if self._severity_rank(alert.severity) > self._severity_rank(existing.severity):
                    existing.severity = alert.severity
                return existing

        # Create new incident
        title = f"Security Incident: {alert.rule_name} from {key}"
        actions = self._generate_recommended_actions(alert)
        incident = Incident(
            title=title,
            created_at=alert.timestamp,
            severity=alert.severity,
            risk_score=alert.risk_score,
            source_ip=alert.source_ip,
            recommended_actions=actions,
            status=IncidentStatus.NEW,
        )
        incident.add_alert(alert)
        self._active_incidents[key] = incident
        self._incidents.append(incident)
        return incident

    def _escalate_ssh_compromise(self, success_event: Event, bf_alert: Alert) -> Incident:
        """Create a Critical Compromise incident for brute-force followed by success."""
        src_ip = success_event.source_ip or "unknown"
        target_user = success_event.user or "unknown"
        host = success_event.host or "unknown"

        factors = {
            "base_compromise_severity": 85.0,
            "brute_force_precursor": 10.0,
            "credential_access_escalation": 5.0,
        }
        risk = RiskScore(
            score=95.0,
            severity=Severity.CRITICAL,
            confidence=0.92,
            factors=factors,
            rationale=(
                f"High-confidence compromise sequence: Multiple SSH authentication failures "
                f"from {src_ip} immediately followed by successful login for user '{target_user}'."
            ),
        )

        tech_compromise = MITREAttack(
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic="Defense Evasion",
            rationale="Adversary successfully authenticated after credential brute-forcing.",
        )

        # Create a dedicated compromise alert to embed
        comp_alert = Alert(
            rule_id="CORR-SSH-002",
            rule_name="Possible SSH Compromise Post-Brute Force",
            timestamp=success_event.timestamp,
            severity=Severity.CRITICAL,
            risk_score=risk,
            source_ip=src_ip,
            target_user=target_user,
            target_host=host,
            mitre_techniques=[tech_compromise],
            evidence_event_ids=list(bf_alert.evidence_event_ids) + [success_event.event_id],
            summary=f"Successful login for '{target_user}' from brute-forcing source {src_ip}",
        )

        incident_id = f"INC-SSH-{uuid.uuid4().hex[:6].upper()}"
        incident = Incident(
            incident_id=incident_id,
            title=f"Critical: Possible SSH Compromise on {host} from {src_ip}",
            created_at=bf_alert.timestamp,
            updated_at=success_event.timestamp,
            severity=Severity.CRITICAL,
            risk_score=risk,
            source_ip=src_ip,
            affected_hosts=[host] if host != "unknown" else [],
            affected_users=[target_user] if target_user != "unknown" else [],
            recommended_actions=[
                f"Isolate host '{host}' immediately from the network.",
                f"Force expire credentials and active SSH keys for user '{target_user}'.",
                "Review active user sessions and recent shell history for persistence commands.",
                f"Search logs for lateral movement from source IP {src_ip}.",
            ],
            status=IncidentStatus.NEW,
        )

        incident.add_alert(bf_alert)
        incident.add_alert(comp_alert)

        # Record in active incidents
        self._active_incidents[src_ip] = incident
        self._incidents.append(incident)
        return incident

    def _generate_recommended_actions(self, alert: Alert) -> list[str]:
        """Generate defensive playbooks based on MITRE techniques and rule metadata."""
        actions: list[str] = []
        rule_lower = alert.rule_name.lower()
        if "sql" in rule_lower:
            actions.extend([
                "Inspect web application logs for HTTP 200/500 response discrepancies.",
                "Review database audit query logs for unauthorized schema extraction.",
                "Check for dropped web shells or modified server artifacts.",
            ])
        elif "traversal" in rule_lower:
            actions.extend([
                "Verify web server access controls and file permissions on targeted paths.",
                "Inspect response status code and length to confirm if files were accessed.",
            ])
        elif "brute" in rule_lower:
            actions.extend([
                "Monitor for follow-up successful authentications from the source IP.",
                "Enforce rate-limiting or IP restriction at edge firewall/WAF.",
            ])
        else:
            actions.append("Review surrounding event telemetry and validate target host integrity.")
        return actions

    @property
    def incidents(self) -> list[Incident]:
        return list(self._incidents)

    def reset_state(self) -> None:
        self._active_incidents.clear()
        self._recent_bruteforce.clear()
        self._incidents.clear()

    @staticmethod
    def _severity_rank(severity: Severity) -> int:
        ranks = {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return ranks.get(severity, 0)
