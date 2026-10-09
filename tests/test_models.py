"""Unit tests for the typed core data models (engine.models).

Verifies validation rules, timezone normalization, MITRE technique handling,
risk score boundary constraints, and serialization/deserialization.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from engine.models import (
    Alert,
    Event,
    EventType,
    Incident,
    IncidentStatus,
    MITREAttack,
    RiskScore,
    Severity,
    ensure_utc,
    format_iso_utc,
)


# --- 1. Timestamp & Timezone Tests --------------------------------------------


def test_ensure_utc_from_naive_datetime():
    naive = datetime(2026, 10, 8, 14, 30, 0)
    utc_dt = ensure_utc(naive)
    assert utc_dt.tzinfo == timezone.utc
    assert utc_dt.hour == 14


def test_ensure_utc_from_iso_strings():
    dt1 = ensure_utc("2026-10-08T14:30:00Z")
    assert dt1.tzinfo == timezone.utc
    assert dt1.year == 2026 and dt1.month == 10 and dt1.day == 8

    dt2 = ensure_utc("2026-10-08T16:30:00+02:00")
    assert dt2.tzinfo == timezone.utc
    assert dt2.hour == 14  # 16:30 +02:00 is 14:30 UTC

    # Legacy syslog format +0000 without colon
    dt3 = ensure_utc("2026-10-08T14:30:00+0000")
    assert dt3.tzinfo == timezone.utc


def test_ensure_utc_invalid_strings():
    with pytest.raises(ValueError, match="Invalid timestamp format"):
        ensure_utc("not-a-timestamp")

    with pytest.raises(ValueError, match="cannot be empty"):
        ensure_utc("   ")

    with pytest.raises(TypeError):
        ensure_utc(123456789)  # type: ignore[arg-type]


def test_format_iso_utc():
    dt = datetime(2026, 10, 8, 9, 0, 0, tzinfo=timezone.utc)
    formatted = format_iso_utc(dt)
    assert formatted == "2026-10-08T09:00:00Z"


# --- 2. Severity & RiskScore Tests --------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [
        (95.0, Severity.CRITICAL),
        (85.0, Severity.CRITICAL),
        (75.0, Severity.HIGH),
        (65.0, Severity.HIGH),
        (50.0, Severity.MEDIUM),
        (40.0, Severity.MEDIUM),
        (25.0, Severity.LOW),
        (15.0, Severity.LOW),
        (5.0, Severity.INFORMATIONAL),
    ],
)
def test_severity_from_score(score, expected):
    assert Severity.from_score(score) == expected


@pytest.mark.parametrize(
    "level,expected",
    [
        (14, Severity.CRITICAL),
        (12, Severity.CRITICAL),
        (10, Severity.HIGH),
        (8, Severity.HIGH),
        (5, Severity.MEDIUM),
        (3, Severity.LOW),
        (0, Severity.INFORMATIONAL),
    ],
)
def test_severity_from_wazuh_level(level, expected):
    assert Severity.from_level(level) == expected


def test_risk_score_valid():
    rs = RiskScore(
        score=78.5,
        severity=Severity.HIGH,
        confidence=0.9,
        factors={"base_severity": 50.0, "frequency_factor": 15.0, "escalation_factor": 13.5},
        rationale="Multiple failed SSH authentications observed from single IP.",
    )
    assert rs.score == 78.5
    assert rs.confidence == 0.9

    data = rs.to_dict()
    assert data["score"] == 78.5
    assert data["severity"] == "high"
    assert data["confidence"] == 0.9
    assert "base_severity" in data["factors"]

    restored = RiskScore.from_dict(data)
    assert restored.score == rs.score
    assert restored.severity == rs.severity
    assert restored.rationale == rs.rationale


def test_risk_score_invalid_boundaries():
    with pytest.raises(ValueError, match="Risk score must be between 0.0 and 100.0"):
        RiskScore(score=105.0, severity=Severity.CRITICAL, confidence=0.8, factors={}, rationale="test")

    with pytest.raises(ValueError, match="Risk score must be between 0.0 and 100.0"):
        RiskScore(score=-5.0, severity=Severity.LOW, confidence=0.8, factors={}, rationale="test")

    with pytest.raises(ValueError, match="Confidence must be between 0.0 and 1.0"):
        RiskScore(score=50.0, severity=Severity.MEDIUM, confidence=1.5, factors={}, rationale="test")

    with pytest.raises(ValueError, match="rationale cannot be empty"):
        RiskScore(score=50.0, severity=Severity.MEDIUM, confidence=0.5, factors={}, rationale="  ")


# --- 3. MITREAttack Tests -----------------------------------------------------


def test_mitre_attack_valid():
    tech = MITREAttack(
        technique_id="T1110.001",
        technique_name="Password Guessing",
        tactic="Credential Access",
        rationale="Automated brute-force attempts targeting SSH service.",
    )
    assert tech.url == "https://attack.mitre.org/techniques/T1110/001/"

    parent_tech = MITREAttack(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
    )
    assert parent_tech.url == "https://attack.mitre.org/techniques/T1110/"

    # Roundtrip serialization
    data = tech.to_dict()
    restored = MITREAttack.from_dict(data)
    assert restored.technique_id == tech.technique_id
    assert restored.url == tech.url


@pytest.mark.parametrize("invalid_id", ["T1", "1110", "T1110.1", "T11100", "attack.t1110", ""])
def test_mitre_attack_invalid_technique_id(invalid_id):
    with pytest.raises(ValueError, match="Invalid MITRE ATT&CK technique ID format"):
        MITREAttack(technique_id=invalid_id, technique_name="Name", tactic="Tactic")


def test_mitre_attack_empty_strings():
    with pytest.raises(ValueError, match="Technique name cannot be empty"):
        MITREAttack(technique_id="T1110", technique_name="   ", tactic="Tactic")
    with pytest.raises(ValueError, match="Tactic cannot be empty"):
        MITREAttack(technique_id="T1110", technique_name="Name", tactic="")


# --- 4. Event Tests -----------------------------------------------------------


def test_event_valid_and_defaults():
    evt = Event(
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=datetime(2026, 10, 8, 14, 0, 0),
        source_ip="192.0.2.15",
        source_port=42101,
        user="admin",
        host="web-01",
        service="sshd",
        action="login_failed",
    )
    assert evt.event_id.startswith("evt-")
    assert evt.timestamp.tzinfo == timezone.utc
    assert evt.source_ip == "192.0.2.15"

    # Serialization roundtrip
    data = evt.to_dict()
    assert data["timestamp"] == "2026-10-08T14:00:00Z"
    assert data["event_type"] == "authentication_failure"

    restored = Event.from_dict(data)
    assert restored.event_id == evt.event_id
    assert restored.event_type == evt.event_type
    assert restored.source_ip == evt.source_ip
    assert restored.timestamp == evt.timestamp

    # JSON export
    raw_json = evt.to_json()
    assert "192.0.2.15" in raw_json


def test_event_invalid_ports():
    with pytest.raises(ValueError, match="source_port must be between 0 and 65535"):
        Event(
            event_type=EventType.AUTHENTICATION_FAILURE,
            timestamp=datetime.now(timezone.utc),
            source_port=70000,
        )

    with pytest.raises(ValueError, match="destination_port must be between 0 and 65535"):
        Event(
            event_type=EventType.AUTHENTICATION_FAILURE,
            timestamp=datetime.now(timezone.utc),
            destination_port=-1,
        )


# --- 5. Alert Tests -----------------------------------------------------------


def test_alert_valid_and_serialization():
    rs = RiskScore(
        score=75.0,
        severity=Severity.HIGH,
        confidence=0.85,
        factors={"base": 70.0, "evidence": 5.0},
        rationale="Threshold matched.",
    )
    technique = MITREAttack(
        technique_id="T1110.001",
        technique_name="Password Guessing",
        tactic="Credential Access",
    )
    alert = Alert(
        rule_id="DET-SSH-001",
        rule_name="SSH Brute Force Detected",
        timestamp=datetime(2026, 10, 8, 14, 0, 32, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        risk_score=rs,
        source_ip="192.0.2.15",
        target_user="deploy",
        target_host="web-01",
        mitre_techniques=[technique],
        evidence_event_ids=["evt-01", "evt-02"],
        summary="8 failed logins from 192.0.2.15 in 32s",
    )
    assert alert.alert_id.startswith("alt-")
    assert len(alert.mitre_techniques) == 1
    assert len(alert.evidence_event_ids) == 2

    data = alert.to_dict()
    assert data["severity"] == "high"
    assert data["risk_score"]["score"] == 75.0
    assert data["mitre_techniques"][0]["technique_id"] == "T1110.001"

    restored = Alert.from_dict(data)
    assert restored.alert_id == alert.alert_id
    assert restored.rule_id == alert.rule_id
    assert restored.mitre_techniques[0].technique_name == "Password Guessing"


def test_alert_validation_failures():
    rs = RiskScore(score=50.0, severity=Severity.MEDIUM, confidence=0.5, factors={}, rationale="ok")
    with pytest.raises(ValueError, match="rule_id cannot be empty"):
        Alert(
            rule_id="",
            rule_name="Test Rule",
            timestamp=datetime.now(timezone.utc),
            severity=Severity.LOW,
            risk_score=rs,
        )

    with pytest.raises(ValueError, match="rule_name cannot be empty"):
        Alert(
            rule_id="DET-001",
            rule_name="   ",
            timestamp=datetime.now(timezone.utc),
            severity=Severity.LOW,
            risk_score=rs,
        )

    with pytest.raises(TypeError, match="must be an instance of RiskScore"):
        Alert(
            rule_id="DET-001",
            rule_name="Test Rule",
            timestamp=datetime.now(timezone.utc),
            severity=Severity.LOW,
            risk_score="not_a_risk_score",  # type: ignore[arg-type]
        )


# --- 6. Incident Tests --------------------------------------------------------


def test_incident_aggregation_and_timeline():
    rs1 = RiskScore(score=70.0, severity=Severity.HIGH, confidence=0.8, factors={}, rationale="Brute force")
    rs2 = RiskScore(score=90.0, severity=Severity.CRITICAL, confidence=0.9, factors={}, rationale="Compromise")

    tech1 = MITREAttack(technique_id="T1110.001", technique_name="Password Guessing", tactic="Credential Access")
    tech2 = MITREAttack(technique_id="T1078", technique_name="Valid Accounts", tactic="Defense Evasion")

    alert1 = Alert(
        rule_id="DET-SSH-001",
        rule_name="SSH Brute Force",
        timestamp=datetime(2026, 10, 8, 14, 0, 30, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        risk_score=rs1,
        source_ip="192.0.2.15",
        target_user="deploy",
        target_host="web-01",
        mitre_techniques=[tech1],
        evidence_event_ids=["evt-01"],
        summary="8 failed logins",
    )

    alert2 = Alert(
        rule_id="DET-SSH-002",
        rule_name="SSH Compromise After Brute Force",
        timestamp=datetime(2026, 10, 8, 14, 0, 45, tzinfo=timezone.utc),
        severity=Severity.CRITICAL,
        risk_score=rs2,
        source_ip="192.0.2.15",
        target_user="deploy",
        target_host="web-01",
        mitre_techniques=[tech1, tech2],  # Note tech1 is repeated to test deduplication
        evidence_event_ids=["evt-02"],
        summary="Successful login from attacking IP",
    )

    incident = Incident(
        title="Probable SSH Compromise on web-01",
        created_at=datetime(2026, 10, 8, 14, 0, 30, tzinfo=timezone.utc),
        severity=Severity.CRITICAL,
        risk_score=rs2,
        recommended_actions=[
            "Isolate host web-01 immediately.",
            "Rotate credentials for user deploy.",
            "Review /var/log/auth.log for lateral movement.",
        ],
    )

    incident.add_alert(alert1)
    incident.add_alert(alert2)

    assert len(incident.alerts) == 2
    # Check deduplication of MITRE techniques: tech1 and tech2 only
    assert len(incident.mitre_techniques) == 2
    technique_ids = {t.technique_id for t in incident.mitre_techniques}
    assert technique_ids == {"T1110.001", "T1078"}

    # Check updated_at matches latest alert
    assert incident.updated_at == alert2.timestamp

    # Check affected entities
    assert incident.source_ip == "192.0.2.15"
    assert incident.affected_hosts == ["web-01"]
    assert incident.affected_users == ["deploy"]

    # Check timeline has 2 entries in order
    assert len(incident.timeline) == 2
    assert incident.timeline[0]["timestamp"] < incident.timeline[1]["timestamp"]

    # Serialization roundtrip
    data = incident.to_dict()
    assert data["title"] == "Probable SSH Compromise on web-01"
    assert data["status"] == "new"
    assert len(data["alerts"]) == 2
    assert len(data["recommended_actions"]) == 3

    restored = Incident.from_dict(data)
    assert restored.incident_id == incident.incident_id
    assert len(restored.alerts) == 2
    assert len(restored.mitre_techniques) == 2
    assert restored.status == IncidentStatus.NEW

    # JSON export
    json_str = incident.to_json()
    parsed_json = json.loads(json_str)
    assert parsed_json["incident_id"] == incident.incident_id
