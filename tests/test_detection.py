"""Unit tests for SentinelForge detection rules and DetectionEngine."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from engine.detection.engine import DetectionEngine
from engine.detection.rules import (
    SSHBruteForceRule,
    WebDirectoryTraversalRule,
    WebSQLInjectionRule,
)
from engine.models import Event, EventType, Severity


def test_ssh_bruteforce_rule_threshold_and_state():
    rule = SSHBruteForceRule(threshold=3, window_seconds=60)
    rule.reset_state()

    # Event 1 & 2: under threshold -> no alert
    e1 = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 10, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        user="root",
        service="sshd",
        action="login_failed",
    )
    e2 = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 20, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        user="admin",
        service="sshd",
        action="login_failed",
    )
    assert rule.evaluate(e1) is None
    assert rule.evaluate(e2) is None

    # Event 3: reaches threshold 3 -> emits alert
    e3 = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 30, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        user="test",
        service="sshd",
        action="login_failed",
    )
    alert = rule.evaluate(e3)
    assert alert is not None
    assert alert.rule_id == "DET-SSH-001"
    assert alert.severity == Severity.HIGH
    assert len(alert.evidence_event_ids) == 3
    assert alert.mitre_techniques[0].technique_id == "T1110.001"

    # Different IP should not inherit count
    diff_ip = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 35, tzinfo=timezone.utc),
        source_ip="198.51.100.20",
        user="root",
        service="sshd",
        action="login_failed",
    )
    assert rule.evaluate(diff_ip) is None


def test_ssh_bruteforce_sliding_window_expiration():
    rule = SSHBruteForceRule(threshold=2, window_seconds=30)
    rule.reset_state()

    # First event at T=0
    e1 = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        service="sshd",
        action="login_failed",
    )
    rule.evaluate(e1)

    # Second event at T=40 (outside 30s window) -> should prune e1, count=1, no alert
    e2 = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 40, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        service="sshd",
        action="login_failed",
    )
    assert rule.evaluate(e2) is None


def test_web_sqli_rule_detects_attacks():
    rule = WebSQLInjectionRule()

    sqli_event = Event(
        event_type=EventType.WEB_REQUEST,
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        service="apache",
        action="http_get",
        metadata={"uri": "/products?id=1' UNION SELECT username,password FROM users--"},
    )
    alert = rule.evaluate(sqli_event)
    assert alert is not None
    assert alert.rule_id == "DET-WEB-001"
    assert alert.mitre_techniques[0].technique_id == "T1190"


def test_web_sqli_rule_ignores_benign_searches():
    rule = WebSQLInjectionRule()

    benign_event = Event(
        event_type=EventType.WEB_REQUEST,
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        source_ip="198.51.100.50",
        service="apache",
        action="http_get",
        metadata={"uri": "/search?q=credit+union+selection"},
    )
    assert rule.evaluate(benign_event) is None


def test_web_directory_traversal_rule():
    rule = WebDirectoryTraversalRule()

    attack_event = Event(
        event_type=EventType.WEB_REQUEST,
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        source_ip="192.0.2.15",
        service="apache",
        action="http_get",
        metadata={"uri": "/static/../../../../etc/passwd"},
    )
    alert = rule.evaluate(attack_event)
    assert alert is not None
    assert alert.rule_id == "DET-WEB-002"

    benign_event = Event(
        event_type=EventType.WEB_REQUEST,
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        source_ip="198.51.100.50",
        service="apache",
        action="http_get",
        metadata={"uri": "/static/css/style.css"},
    )
    assert rule.evaluate(benign_event) is None


def test_detection_engine_stream_processing():
    engine = DetectionEngine()
    engine.reset_state()

    events = [
        Event(
            event_type=EventType.WEB_REQUEST,
            timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
            source_ip="192.0.2.15",
            metadata={"uri": "/api?id=1 UNION SELECT 1,2"},
        ),
        Event(
            event_type=EventType.WEB_REQUEST,
            timestamp=datetime(2026, 10, 8, 14, 0, 1, tzinfo=timezone.utc),
            source_ip="192.0.2.15",
            metadata={"uri": "/files/../../win.ini"},
        ),
    ]

    alerts = engine.process_stream(events)
    assert len(alerts) == 2
    rule_ids = {a.rule_id for a in alerts}
    assert rule_ids == {"DET-WEB-001", "DET-WEB-002"}
