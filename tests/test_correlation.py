"""Unit tests for EventCorrelator and incident lifecycle management."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from engine.correlation.correlator import EventCorrelator
from engine.detection.rules import SSHBruteForceRule
from engine.models import Alert, Event, EventType, MITREAttack, RiskScore, Severity


def test_standard_incident_aggregation():
    correlator = EventCorrelator(correlation_window_seconds=120)
    correlator.reset_state()

    rs = RiskScore(score=60.0, severity=Severity.MEDIUM, confidence=0.8, factors={}, rationale="test")
    alt1 = Alert(
        rule_id="DET-WEB-001",
        rule_name="Web SQL Injection",
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        risk_score=rs,
        source_ip="192.0.2.15",
        summary="SQLi 1",
    )
    alt2 = Alert(
        rule_id="DET-WEB-002",
        rule_name="Directory Traversal",
        timestamp=datetime(2026, 10, 8, 14, 0, 30, tzinfo=timezone.utc),
        severity=Severity.MEDIUM,
        risk_score=rs,
        source_ip="192.0.2.15",
        summary="Traversal 1",
    )

    dummy_evt = Event(event_type=EventType.WEB_REQUEST, timestamp=alt1.timestamp, source_ip="192.0.2.15")

    incidents1 = correlator.process(dummy_evt, [alt1])
    assert len(incidents1) == 1
    inc1 = incidents1[0]
    assert len(inc1.alerts) == 1

    dummy_evt2 = Event(event_type=EventType.WEB_REQUEST, timestamp=alt2.timestamp, source_ip="192.0.2.15")
    incidents2 = correlator.process(dummy_evt2, [alt2])
    assert len(incidents2) == 1
    assert incidents2[0].incident_id == inc1.incident_id  # Aggregated into same incident
    assert len(incidents2[0].alerts) == 2


def test_ssh_compromise_sequence_escalation():
    correlator = EventCorrelator(ssh_compromise_window_seconds=120)
    correlator.reset_state()

    # Step 1: Generate Brute Force Alert
    rule = SSHBruteForceRule(threshold=2, window_seconds=60)
    e1 = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        service="sshd",
        action="login_failed",
    )
    e2 = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 5, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        service="sshd",
        action="login_failed",
    )
    rule.evaluate(e1)
    bf_alert = rule.evaluate(e2)
    assert bf_alert is not None

    correlator.process(e2, [bf_alert])

    # Step 2: Successful login from same IP shortly after (T=30s)
    success_event = Event(
        event_type=EventType.AUTHENTICATION_SUCCESS,
        timestamp=datetime(2026, 10, 8, 14, 0, 30, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        user="deploy",
        host="web-01",
        service="sshd",
        action="login_success",
    )

    incidents = correlator.process(success_event, [])
    assert len(incidents) == 1
    compromise_inc = incidents[0]
    assert compromise_inc.severity == Severity.CRITICAL
    assert compromise_inc.risk_score.score >= 90.0
    assert "Critical: Possible SSH Compromise" in compromise_inc.title
    assert "deploy" in compromise_inc.affected_users

    # Verify MITRE techniques include both T1110.001 and T1078
    tech_ids = {t.technique_id for t in compromise_inc.mitre_techniques}
    assert "T1110.001" in tech_ids
    assert "T1078" in tech_ids
