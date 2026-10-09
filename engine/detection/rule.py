"""Base rule interface and abstractions for SentinelForge detection engine."""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from engine.models import Alert, Event, MITREAttack, RiskScore, Severity


class BaseRule(ABC):
    """Abstract base class for all SentinelForge detection rules."""

    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    base_score: float
    confidence: float
    mitre_techniques: list[MITREAttack]

    def __init__(self) -> None:
        if not hasattr(self, "rule_id") or not self.rule_id:
            raise ValueError("Rule must define a non-empty rule_id")
        if not hasattr(self, "rule_name") or not self.rule_name:
            raise ValueError("Rule must define a non-empty rule_name")
        if not hasattr(self, "mitre_techniques"):
            self.mitre_techniques = []

    @abstractmethod
    def evaluate(self, event: Event) -> Alert | None:
        """Evaluate an incoming normalized event.

        Returns:
            Alert if detection condition is met, None otherwise.
        """
        ...

    def create_alert(
        self,
        event: Event,
        summary: str,
        custom_factors: dict[str, float] | None = None,
        rationale: str | None = None,
        extra_metadata: dict[str, Any] | None = None,
        evidence_event_ids: list[str] | None = None,
    ) -> Alert:
        """Helper to create a well-formed Alert from a matched Event."""
        factors = custom_factors or {
            "base_severity": self.base_score,
            "rule_confidence": self.confidence * 20.0,
        }
        computed_score = min(100.0, max(0.0, sum(factors.values())))
        alert_rationale = rationale or f"Rule {self.rule_id} triggered: {summary}"

        risk = RiskScore(
            score=computed_score,
            severity=self.severity,
            confidence=self.confidence,
            factors=factors,
            rationale=alert_rationale,
        )

        metadata = dict(event.metadata)
        if extra_metadata:
            metadata.update(extra_metadata)

        ev_ids = evidence_event_ids or [event.event_id]

        return Alert(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            timestamp=event.timestamp,
            severity=self.severity,
            risk_score=risk,
            source_ip=event.source_ip,
            target_user=event.user,
            target_host=event.host,
            mitre_techniques=list(self.mitre_techniques),
            evidence_event_ids=ev_ids,
            summary=summary,
            metadata=metadata,
        )
