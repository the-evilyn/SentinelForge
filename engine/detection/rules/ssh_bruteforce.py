"""Rule DET-SSH-001: SSH Brute Force Detection."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from engine.detection.rule import BaseRule
from engine.models import Alert, Event, EventType, MITREAttack, Severity


class SSHBruteForceRule(BaseRule):
    """Detects repeated SSH authentication failures from a single source within a sliding window."""

    rule_id = "DET-SSH-001"
    rule_name = "SSH Authentication Failure Threshold (Brute Force)"
    description = "Detects multiple failed SSH authentication attempts from a single source IP within a sliding time window."
    severity = Severity.HIGH
    base_score = 65.0
    confidence = 0.85

    mitre_techniques = [
        MITREAttack(
            technique_id="T1110.001",
            technique_name="Password Guessing",
            tactic="Credential Access",
            rationale="Repeated authentication failures indicate automated password guessing or credential spraying.",
        )
    ]

    def __init__(self, threshold: int = 5, window_seconds: int = 120) -> None:
        super().__init__()
        self.threshold = threshold
        self.window_seconds = window_seconds
        # Mapping: source_ip -> list of (timestamp, event_id)
        self._history: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

    def evaluate(self, event: Event) -> Alert | None:
        if event.event_type != EventType.AUTHENTICATION_FAILURE:
            return None
        if event.service != "sshd" and event.action != "login_failed":
            return None

        src_ip = event.source_ip
        if not src_ip:
            return None

        current_time = event.timestamp
        # Prune events outside sliding window
        window_start = current_time.timestamp() - self.window_seconds
        self._history[src_ip] = [
            (ts, eid) for ts, eid in self._history[src_ip] if ts.timestamp() >= window_start
        ]

        # Add current event
        self._history[src_ip].append((current_time, event.event_id))

        count = len(self._history[src_ip])
        if count >= self.threshold:
            evidence_ids = [eid for _, eid in self._history[src_ip]]
            summary = (
                f"SSH brute-force activity detected: {count} failed authentications from "
                f"{src_ip} within {self.window_seconds}s"
            )
            freq_factor = min(20.0, float(count * 2))
            factors = {
                "base_severity": self.base_score,
                "frequency_boost": freq_factor,
                "confidence_weight": self.confidence * 10.0,
            }
            return self.create_alert(
                event=event,
                summary=summary,
                custom_factors=factors,
                evidence_event_ids=evidence_ids,
                extra_metadata={"failure_count": count, "window_seconds": self.window_seconds},
            )

        return None

    def reset_state(self) -> None:
        """Clear state history (useful between test cases or dataset replays)."""
        self._history.clear()
