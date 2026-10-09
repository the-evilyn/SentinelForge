"""Unit tests for AlertDeduplicator and allowlist management."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from engine.models import Alert, RiskScore, Severity
from engine.suppression.deduplicator import AlertDeduplicator


def test_deduplicator_window_suppression():
    dedup = AlertDeduplicator(suppression_window_seconds=60)
    rs = RiskScore(score=70.0, severity=Severity.HIGH, confidence=0.8, factors={}, rationale="test")

    alert1 = Alert(
        rule_id="DET-SSH-001",
        rule_name="SSH Brute Force",
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        risk_score=rs,
        source_ip="192.0.2.15",
    )
    # First alert should forward
    fwd1, r1 = dedup.should_forward(alert1)
    assert fwd1 is True
    assert "Forward" in r1

    # Second identical alert 20 seconds later should be suppressed
    alert2 = Alert(
        rule_id="DET-SSH-001",
        rule_name="SSH Brute Force",
        timestamp=datetime(2026, 10, 8, 14, 0, 20, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        risk_score=rs,
        source_ip="192.0.2.15",
    )
    fwd2, r2 = dedup.should_forward(alert2)
    assert fwd2 is False
    assert "Suppressed duplicate" in r2

    # Third alert 70 seconds later should forward (window expired)
    alert3 = Alert(
        rule_id="DET-SSH-001",
        rule_name="SSH Brute Force",
        timestamp=datetime(2026, 10, 8, 14, 1, 10, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        risk_score=rs,
        source_ip="192.0.2.15",
    )
    fwd3, r3 = dedup.should_forward(alert3)
    assert fwd3 is True

    assert dedup.total_evaluated == 3
    assert dedup.forwarded_count == 2
    assert dedup.suppressed_count == 1


def test_deduplicator_allowlists():
    dedup = AlertDeduplicator()
    rs = RiskScore(score=50.0, severity=Severity.MEDIUM, confidence=0.8, factors={}, rationale="test")

    # Localhost IP alert
    alt_local = Alert(
        rule_id="DET-WEB-001",
        rule_name="Web Scan",
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        severity=Severity.MEDIUM,
        risk_score=rs,
        source_ip="127.0.0.1",
    )
    fwd, reason = dedup.should_forward(alt_local)
    assert fwd is False
    assert "Allowlisted source IP" in reason

    # Backup service account alert
    alt_user = Alert(
        rule_id="DET-SSH-001",
        rule_name="SSH Attempt",
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        severity=Severity.LOW,
        risk_score=rs,
        target_user="backup_svc",
    )
    fwd_user, reason_user = dedup.should_forward(alt_user)
    assert fwd_user is False
    assert "Allowlisted user" in reason_user
