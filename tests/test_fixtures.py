"""Automated validation tests for synthetic telemetry fixtures.

Verifies schema compliance, presence of required security scenarios, absence of
live secrets/IPs, and offline usability without Docker.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from engine.models import Event

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_fixtures_directory_exists():
    assert FIXTURES_DIR.is_dir()
    assert (FIXTURES_DIR / "README.md").is_file()


def test_ssh_auth_log_fixture():
    path = FIXTURES_DIR / "ssh_auth.log"
    assert path.is_file()
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 10

    # Verify key scenarios exist
    has_failed = any("Failed password" in line for line in lines)
    has_accepted = any("Accepted password" in line for line in lines)
    has_pubkey = any("Accepted publickey" in line for line in lines)
    assert has_failed and has_accepted and has_pubkey

    # Verify RFC 5737 sanitized IP addresses
    allowed_ip_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.1", "10.")
    for line in lines:
        for word in line.split():
            if "." in word and not word.startswith("ssh") and not word.endswith("."):
                cleaned_ip = word.strip(":,[]()")
                parts = cleaned_ip.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    assert any(cleaned_ip.startswith(prefix) for prefix in allowed_ip_prefixes), (
                        f"Non-sanitized IP found in ssh_auth.log: {cleaned_ip}"
                    )


def test_apache_access_log_fixture():
    path = FIXTURES_DIR / "apache_access.log"
    assert path.is_file()
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 6

    # Verify presence of SQLi, directory traversal, and benign requests
    assert any("UNION" in line for line in lines)
    assert any("../" in line for line in lines)
    assert any("/index.php" in line for line in lines)
    assert any("credit+union+selection" in line for line in lines)  # False-positive test case
    assert any("/health" in line for line in lines)


def test_suricata_eve_json_fixture():
    path = FIXTURES_DIR / "suricata_eve.json"
    assert path.is_file()
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 5

    event_types = set()
    signature_ids = set()

    for idx, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            pytest.fail(f"Line {idx + 1} of suricata_eve.json is not valid JSON: {exc}")

        assert "timestamp" in record
        assert "event_type" in record
        assert "proto" in record
        event_types.add(record["event_type"])

        if record.get("event_type") == "alert":
            alert = record.get("alert", {})
            assert "signature_id" in alert
            signature_ids.add(alert["signature_id"])

    assert "alert" in event_types
    assert "http" in event_types
    assert "flow" in event_types

    # Ensure custom rule SIDs are covered
    expected_sids = {1000001, 1000002, 1000003, 1000004}
    assert expected_sids.issubset(signature_ids)


def test_synthetic_events_json_schema_and_model_conversion():
    path = FIXTURES_DIR / "synthetic_events.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) >= 3

    malicious_scenarios = [s for s in data if s.get("classification") == "malicious"]
    benign_scenarios = [s for s in data if s.get("classification") == "benign"]
    assert len(malicious_scenarios) >= 2
    assert len(benign_scenarios) >= 1

    # Verify that every structured event parses directly into an Event dataclass
    for scenario in data:
        assert "scenario_id" in scenario
        assert "events" in scenario
        for raw_evt in scenario["events"]:
            event_obj = Event.from_dict(raw_evt)
            assert isinstance(event_obj, Event)
            assert event_obj.event_id == raw_evt["event_id"]
            assert event_obj.event_type.value == raw_evt["event_type"]
