"""Core typed data models for the SOC Detection & Correlation Engine.

Standard library only. Provides typed, validated models for security events,
alerts, correlated incidents, MITRE ATT&CK technique mappings, and explainable
risk scores.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

MITRE_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def ensure_utc(dt: datetime | str) -> datetime:
    """Normalize a datetime or ISO-8601 string to a timezone-aware UTC datetime.

    Accepts:
    - datetime instances (naive assumed UTC, aware converted to UTC)
    - ISO-8601 strings (e.g. '2026-10-08T14:00:00Z', '2026-10-08T14:00:00+00:00')

    Raises:
        ValueError: If the string format cannot be parsed as a valid ISO timestamp.
    """
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    if isinstance(dt, str):
        cleaned = dt.strip()
        if not cleaned:
            raise ValueError("Timestamp string cannot be empty")
        # Standardize Z to +00:00 for fromisoformat compatibility across Python versions
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(cleaned)
        except ValueError as exc:
            # Fallback for Suricata/syslog formats with +0000 without colon
            if re.search(r"[+-]\d{4}$", cleaned):
                cleaned_tz = cleaned[:-2] + ":" + cleaned[-2:]
                try:
                    parsed = datetime.fromisoformat(cleaned_tz)
                except ValueError:
                    raise ValueError(f"Invalid timestamp format: '{dt}'") from exc
            else:
                raise ValueError(f"Invalid timestamp format: '{dt}'") from exc

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    raise TypeError(f"Expected datetime or str, got {type(dt).__name__}")


def format_iso_utc(dt: datetime) -> str:
    """Format a datetime as an ISO-8601 string with UTC 'Z' suffix."""
    utc_dt = ensure_utc(dt)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class EventType(str, Enum):
    """Normalized security telemetry event categories."""

    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHENTICATION_SUCCESS = "authentication_success"
    WEB_REQUEST = "web_request"
    NETWORK_ALERT = "network_alert"
    NETWORK_FLOW = "network_flow"
    COMMAND_EXECUTION = "command_execution"
    GENERIC = "generic"


class Severity(str, Enum):
    """Standardized severity bands."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> Severity:
        """Map a numeric risk score (0-100) to a Severity band."""
        if score >= 85.0:
            return cls.CRITICAL
        if score >= 65.0:
            return cls.HIGH
        if score >= 40.0:
            return cls.MEDIUM
        if score >= 15.0:
            return cls.LOW
        return cls.INFORMATIONAL

    @classmethod
    def from_level(cls, level: int) -> Severity:
        """Map a Wazuh rule level (0-15) to a Severity band."""
        if level >= 12:
            return cls.CRITICAL
        if level >= 8:
            return cls.HIGH
        if level >= 5:
            return cls.MEDIUM
        if level > 0:
            return cls.LOW
        return cls.INFORMATIONAL


class IncidentStatus(str, Enum):
    """Lifecycle status of a correlated incident."""

    NEW = "new"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    CLOSED = "closed"


@dataclass(frozen=True)
class MITREAttack:
    """Reference to a documented MITRE ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactic: str
    url: str = ""
    rationale: str = ""

    def __post_init__(self) -> None:
        if not MITRE_TECHNIQUE_PATTERN.match(self.technique_id):
            raise ValueError(
                f"Invalid MITRE ATT&CK technique ID format: '{self.technique_id}'. "
                "Must match 'T####' or 'T####.###' (e.g. T1110 or T1110.001)."
            )
        if not self.technique_name.strip():
            raise ValueError("Technique name cannot be empty")
        if not self.tactic.strip():
            raise ValueError("Tactic cannot be empty")

        # Auto-compute standard MITRE ATT&CK URL if not explicitly provided
        if not self.url:
            parts = self.technique_id.split(".")
            if len(parts) == 2:
                computed = f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
            else:
                computed = f"https://attack.mitre.org/techniques/{parts[0]}/"
            object.__setattr__(self, "url", computed)

    def to_dict(self) -> dict[str, str]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "url": self.url,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MITREAttack:
        return cls(
            technique_id=str(data["technique_id"]),
            technique_name=str(data["technique_name"]),
            tactic=str(data["tactic"]),
            url=str(data.get("url", "")),
            rationale=str(data.get("rationale", "")),
        )


@dataclass(frozen=True)
class RiskScore:
    """Transparent, explainable risk score calculation."""

    score: float
    severity: Severity
    confidence: float
    factors: dict[str, float]
    rationale: str

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 100.0):
            raise ValueError(f"Risk score must be between 0.0 and 100.0, got {self.score}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if not self.rationale.strip():
            raise ValueError("Risk score rationale cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "factors": {k: round(v, 2) for k, v in self.factors.items()},
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskScore:
        sev = data["severity"]
        severity_obj = Severity(sev) if isinstance(sev, str) else sev
        return cls(
            score=float(data["score"]),
            severity=severity_obj,
            confidence=float(data["confidence"]),
            factors={str(k): float(v) for k, v in data.get("factors", {}).items()},
            rationale=str(data["rationale"]),
        )


@dataclass
class Event:
    """Normalized security telemetry event."""

    event_type: EventType
    timestamp: datetime
    event_id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    user: str | None = None
    host: str | None = None
    service: str | None = None
    action: str | None = None
    raw_log: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.timestamp = ensure_utc(self.timestamp)

        if not isinstance(self.event_type, EventType):
            if isinstance(self.event_type, str):
                self.event_type = EventType(self.event_type)
            else:
                raise TypeError(f"Invalid event_type: {self.event_type}")

        for port_name, port_val in (("source_port", self.source_port), ("destination_port", self.destination_port)):
            if port_val is not None and not (0 <= port_val <= 65535):
                raise ValueError(f"{port_name} must be between 0 and 65535, got {port_val}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": format_iso_utc(self.timestamp),
            "event_type": self.event_type.value,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "user": self.user,
            "host": self.host,
            "service": self.service,
            "action": self.action,
            "raw_log": self.raw_log,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        return cls(
            event_id=str(data.get("event_id") or f"evt-{uuid.uuid4().hex[:12]}"),
            timestamp=ensure_utc(data["timestamp"]),
            event_type=EventType(data["event_type"]),
            source_ip=data.get("source_ip"),
            source_port=int(data["source_port"]) if data.get("source_port") is not None else None,
            destination_ip=data.get("destination_ip"),
            destination_port=int(data["destination_port"]) if data.get("destination_port") is not None else None,
            user=data.get("user"),
            host=data.get("host"),
            service=data.get("service"),
            action=data.get("action"),
            raw_log=str(data.get("raw_log", "")),
            metadata=dict(data.get("metadata", {})),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class Alert:
    """Detection alert generated from an event matching a security rule."""

    rule_id: str
    rule_name: str
    timestamp: datetime
    severity: Severity
    risk_score: RiskScore
    alert_id: str = field(default_factory=lambda: f"alt-{uuid.uuid4().hex[:12]}")
    source_ip: str | None = None
    target_user: str | None = None
    target_host: str | None = None
    mitre_techniques: list[MITREAttack] = field(default_factory=list)
    evidence_event_ids: list[str] = field(default_factory=list)
    summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.timestamp = ensure_utc(self.timestamp)
        if not self.rule_id.strip():
            raise ValueError("Alert rule_id cannot be empty")
        if not self.rule_name.strip():
            raise ValueError("Alert rule_name cannot be empty")
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if not isinstance(self.risk_score, RiskScore):
            raise TypeError("Alert risk_score must be an instance of RiskScore")

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "timestamp": format_iso_utc(self.timestamp),
            "severity": self.severity.value,
            "risk_score": self.risk_score.to_dict(),
            "source_ip": self.source_ip,
            "target_user": self.target_user,
            "target_host": self.target_host,
            "mitre_techniques": [m.to_dict() for m in self.mitre_techniques],
            "evidence_event_ids": list(self.evidence_event_ids),
            "summary": self.summary,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        techniques = [MITREAttack.from_dict(m) for m in data.get("mitre_techniques", [])]
        return cls(
            alert_id=str(data.get("alert_id") or f"alt-{uuid.uuid4().hex[:12]}"),
            rule_id=str(data["rule_id"]),
            rule_name=str(data["rule_name"]),
            timestamp=ensure_utc(data["timestamp"]),
            severity=Severity(data["severity"]),
            risk_score=RiskScore.from_dict(data["risk_score"]),
            source_ip=data.get("source_ip"),
            target_user=data.get("target_user"),
            target_host=data.get("target_host"),
            mitre_techniques=techniques,
            evidence_event_ids=list(data.get("evidence_event_ids", [])),
            summary=str(data.get("summary", "")),
            metadata=dict(data.get("metadata", {})),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class Incident:
    """Correlated group of related alerts representing a security incident."""

    title: str
    created_at: datetime
    severity: Severity
    risk_score: RiskScore
    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    updated_at: datetime | None = None
    alerts: list[Alert] = field(default_factory=list)
    mitre_techniques: list[MITREAttack] = field(default_factory=list)
    source_ip: str | None = None
    affected_hosts: list[str] = field(default_factory=list)
    affected_users: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    status: IncidentStatus = IncidentStatus.NEW

    def __post_init__(self) -> None:
        self.created_at = ensure_utc(self.created_at)
        if self.updated_at is None:
            self.updated_at = self.created_at
        else:
            self.updated_at = ensure_utc(self.updated_at)

        if not self.title.strip():
            raise ValueError("Incident title cannot be empty")
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.status, str):
            self.status = IncidentStatus(self.status)
        if not isinstance(self.risk_score, RiskScore):
            raise TypeError("Incident risk_score must be an instance of RiskScore")

    def add_alert(self, alert: Alert) -> None:
        """Add a correlated alert and update incident timeline and affected assets."""
        self.alerts.append(alert)
        self.updated_at = max(self.updated_at, alert.timestamp)

        # Deduplicate MITRE techniques
        existing_ids = {t.technique_id for t in self.mitre_techniques}
        for technique in alert.mitre_techniques:
            if technique.technique_id not in existing_ids:
                self.mitre_techniques.append(technique)
                existing_ids.add(technique.technique_id)

        # Update affected entities
        if alert.source_ip and not self.source_ip:
            self.source_ip = alert.source_ip
        if alert.target_host and alert.target_host not in self.affected_hosts:
            self.affected_hosts.append(alert.target_host)
        if alert.target_user and alert.target_user not in self.affected_users:
            self.affected_users.append(alert.target_user)

        # Append to timeline
        self.timeline.append({
            "timestamp": format_iso_utc(alert.timestamp),
            "type": "alert",
            "ref_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "summary": alert.summary or alert.rule_name,
            "severity": alert.severity.value,
        })
        self.timeline.sort(key=lambda item: item["timestamp"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "status": self.status.value,
            "created_at": format_iso_utc(self.created_at),
            "updated_at": format_iso_utc(self.updated_at),
            "severity": self.severity.value,
            "risk_score": self.risk_score.to_dict(),
            "source_ip": self.source_ip,
            "affected_hosts": list(self.affected_hosts),
            "affected_users": list(self.affected_users),
            "mitre_techniques": [t.to_dict() for t in self.mitre_techniques],
            "alerts": [a.to_dict() for a in self.alerts],
            "timeline": list(self.timeline),
            "recommended_actions": list(self.recommended_actions),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        alerts = [Alert.from_dict(a) for a in data.get("alerts", [])]
        techniques = [MITREAttack.from_dict(t) for t in data.get("mitre_techniques", [])]
        return cls(
            incident_id=str(data["incident_id"]),
            title=str(data["title"]),
            status=IncidentStatus(data.get("status", "new")),
            created_at=ensure_utc(data["created_at"]),
            updated_at=ensure_utc(data.get("updated_at") or data["created_at"]),
            severity=Severity(data["severity"]),
            risk_score=RiskScore.from_dict(data["risk_score"]),
            source_ip=data.get("source_ip"),
            affected_hosts=list(data.get("affected_hosts", [])),
            affected_users=list(data.get("affected_users", [])),
            mitre_techniques=techniques,
            alerts=alerts,
            timeline=list(data.get("timeline", [])),
            recommended_actions=list(data.get("recommended_actions", [])),
        )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
