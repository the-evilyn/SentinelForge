"""Unit tests for IncidentReporter and evidence integrity hashing."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from engine.models import Event, EventType, Incident, MITREAttack, RiskScore, Severity
from engine.reporting.reporter import IncidentReporter


def test_reporter_json_and_evidence_hash():
    reporter = IncidentReporter()
    rs = RiskScore(
        score=92.0,
        severity=Severity.CRITICAL,
        confidence=0.9,
        factors={"base_severity": 85.0, "sequence_boost": 7.0},
        rationale="Critical SSH brute force and compromise sequence.",
    )
    incident = Incident(
        incident_id="INC-20261008-01",
        title="SSH Compromise on web-01",
        created_at=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        severity=Severity.CRITICAL,
        risk_score=rs,
        source_ip="192.0.2.15",
        recommended_actions=["Isolate host.", "Rotate credentials."],
    )

    ev1 = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        raw_log="Failed password for admin",
    )
    ev2 = Event(
        event_type=EventType.AUTHENTICATION_SUCCESS,
        timestamp=datetime(2026, 10, 8, 14, 0, 30, tzinfo=timezone.utc),
        raw_log="Accepted password for deploy",
    )

    json_str = reporter.generate_json_report(incident, [ev1, ev2])
    data = json.loads(json_str)

    assert data["incident_id"] == "INC-20261008-01"
    assert data["severity"] == "critical"
    assert "evidence_integrity" in data
    assert data["evidence_integrity"]["event_count"] == 2
    assert len(data["evidence_integrity"]["sha256_hash"]) == 64


def test_reporter_markdown_sections():
    reporter = IncidentReporter()
    rs = RiskScore(
        score=75.0,
        severity=Severity.HIGH,
        confidence=0.85,
        factors={"base_severity": 70.0},
        rationale="SQL Injection detected.",
    )
    tech = MITREAttack(technique_id="T1190", technique_name="Exploit Public-Facing App", tactic="Initial Access")
    incident = Incident(
        incident_id="INC-WEB-01",
        title="Web SQL Injection on dvwa",
        created_at=datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        risk_score=rs,
        mitre_techniques=[tech],
        recommended_actions=["Check database query logs."],
    )

    md = reporter.generate_markdown_report(incident)
    assert "# Incident Report: INC-WEB-01" in md
    assert "## 1. Executive Summary & Risk Assessment" in md
    assert "## 2. MITRE ATT&CK Mapping" in md
    assert "T1190" in md
    assert "## 4. Recommended Defensive Actions" in md
