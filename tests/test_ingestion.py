"""Unit tests for the ingestion and normalization layers.

Tests all format parsers (Linux auth, Apache combined, Suricata EVE, Wazuh alerts),
error handling for malformed input, line rejection counters, and canonical
event normalization.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from engine.ingestion import (
    ApacheLogParser,
    AuthLogParser,
    SuricataEveParser,
    WazuhAlertsParser,
)
from engine.models import EventType
from engine.normalization import EventNormalizer, ingest_and_normalize

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# --- 1. AuthLogParser Tests ---------------------------------------------------


def test_auth_log_parser_valid_events():
    parser = AuthLogParser(default_year=2026)
    lines = [
        "Oct 08 14:00:01 web-01 sshd[28101]: Failed password for invalid user admin from 192.0.2.15 port 42101 ssh2",
        "Oct 08 14:00:45 web-01 sshd[28115]: Accepted password for deploy from 192.0.2.15 port 42110 ssh2",
        "Oct 08 14:05:00 web-01 sshd[28130]: Accepted publickey for backup_svc from 198.51.100.75 port 51234 ssh2: RSA SHA256:dummy",
    ]
    result = parser.parse_stream(lines)
    assert result.total_lines == 3
    assert result.success_count == 3
    assert result.error_count == 0

    r1 = result.records[0]
    assert r1.raw_data["action"] == "login_failed"
    assert r1.raw_data["user"] == "admin"
    assert r1.raw_data["src_ip"] == "192.0.2.15"
    assert r1.raw_data["src_port"] == 42101
    assert r1.raw_data["is_invalid_user"] is True

    r2 = result.records[1]
    assert r2.raw_data["action"] == "login_success"
    assert r2.raw_data["user"] == "deploy"

    r3 = result.records[2]
    assert r3.raw_data["action"] == "login_success"
    assert r3.raw_data["auth_method"] == "publickey"


def test_auth_log_parser_malformed_and_resilient():
    parser = AuthLogParser(default_year=2026)
    lines = [
        "Oct 08 14:00:01 web-01 sshd[28101]: Failed password for invalid user admin from 192.0.2.15 port 42101 ssh2",
        "This is a totally invalid, non-syslog garbage log line",
        "",  # blank line should be skipped silently
        "Oct 08 14:00:45 web-01 sshd[28115]: Accepted password for deploy from 192.0.2.15 port 42110 ssh2",
    ]
    result = parser.parse_stream(lines)
    assert result.total_lines == 4
    assert result.success_count == 2
    assert result.error_count == 1
    assert result.errors[0].line_number == 2
    assert "RFC 3164" in result.errors[0].error_message


# --- 2. ApacheLogParser Tests -------------------------------------------------


def test_apache_log_parser_valid_events():
    parser = ApacheLogParser()
    lines = [
        '192.0.2.15 - - [08/Oct/2026:14:00:10 +0000] "GET /vulnerabilities/sqli/?id=1 HTTP/1.1" 200 4812 "http://dvwa.lab/" "sqlmap/1.7"',
        '198.51.100.50 - alice [08/Oct/2026:14:05:00 +0000] "POST /login HTTP/1.1" 302 240 "-" "Mozilla/5.0"',
    ]
    result = parser.parse_stream(lines)
    assert result.success_count == 2
    assert result.error_count == 0

    r1 = result.records[0]
    assert r1.raw_data["src_ip"] == "192.0.2.15"
    assert r1.raw_data["method"] == "GET"
    assert r1.raw_data["status_code"] == 200
    assert r1.raw_data["bytes_sent"] == 4812

    r2 = result.records[1]
    assert r2.raw_data["remote_user"] == "alice"
    assert r2.raw_data["status_code"] == 302


def test_apache_log_parser_malformed():
    parser = ApacheLogParser()
    lines = [
        "192.0.2.15 invalid line without quotes or brackets",
    ]
    result = parser.parse_stream(lines)
    assert result.success_count == 0
    assert result.error_count == 1
    assert "Combined Log" in result.errors[0].error_message


# --- 3. SuricataEveParser Tests -----------------------------------------------


def test_suricata_eve_parser_valid_and_malformed():
    parser = SuricataEveParser()
    valid_alert = json.dumps({
        "timestamp": "2026-10-08T14:00:00.100123+0000",
        "event_type": "alert",
        "src_ip": "192.0.2.15",
        "src_port": 49152,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {"signature_id": 1000001, "signature": "Port scan"},
    })
    malformed_json = "{'bad_json': true,"
    missing_keys = json.dumps({"src_ip": "192.0.2.15"})

    result = parser.parse_stream([valid_alert, malformed_json, missing_keys])
    assert result.total_lines == 3
    assert result.success_count == 1
    assert result.error_count == 2
    assert result.records[0].raw_data["src_ip"] == "192.0.2.15"
    assert result.records[0].raw_data["alert"]["signature_id"] == 1000001


# --- 4. WazuhAlertsParser Tests -----------------------------------------------


def test_wazuh_alerts_parser_valid_and_non_alert():
    parser = WazuhAlertsParser()
    valid_alert = json.dumps({
        "timestamp": "2026-10-08T14:00:00+0000",
        "rule": {"id": "100100", "level": 12, "description": "SSH Brute Force", "groups": ["authentication_failures"]},
        "agent": {"name": "web-01", "id": "001"},
        "data": {"srcip": "192.0.2.15"},
    })
    non_security = json.dumps({"info": "heartbeat"})

    result = parser.parse_stream([valid_alert, non_security])
    assert result.success_count == 1
    assert result.error_count == 1
    assert result.records[0].raw_data["rule_id"] == "100100"
    assert result.records[0].raw_data["level"] == 12


# --- 5. EventNormalizer Tests -------------------------------------------------


def test_normalization_from_fixture_files():
    normalizer = EventNormalizer()

    # Test Linux Auth normalization
    auth_parser = AuthLogParser(default_year=2026)
    auth_result = auth_parser.parse_file(FIXTURES_DIR / "ssh_auth.log")
    assert auth_result.success_count >= 10
    auth_events = normalizer.normalize_batch(auth_result.records)
    assert len(auth_events) == auth_result.success_count

    # Verify event types and UTC timezone
    assert auth_events[0].event_type == EventType.AUTHENTICATION_FAILURE
    assert auth_events[0].source_ip == "192.0.2.15"
    assert auth_events[0].destination_port == 22
    assert auth_events[0].timestamp.tzinfo is not None

    # Test Apache normalization
    web_parser = ApacheLogParser()
    web_result = web_parser.parse_file(FIXTURES_DIR / "apache_access.log")
    assert web_result.success_count >= 6
    web_events = normalizer.normalize_batch(web_result.records)
    assert web_events[0].event_type == EventType.WEB_REQUEST
    assert web_events[0].destination_port == 80
    assert web_events[0].service == "apache"

    # Test Suricata normalization
    eve_parser = SuricataEveParser()
    eve_result = eve_parser.parse_file(FIXTURES_DIR / "suricata_eve.json")
    assert eve_result.success_count >= 5
    eve_events = normalizer.normalize_batch(eve_result.records)
    alert_events = [e for e in eve_events if e.event_type == EventType.NETWORK_ALERT]
    assert len(alert_events) >= 3


def test_ingest_and_normalize_pipeline_helper():
    parser = AuthLogParser(default_year=2026)
    lines = [
        "Oct 08 14:00:01 web-01 sshd[28101]: Failed password for invalid user admin from 192.0.2.15 port 42101 ssh2",
        "GARBAGE_LINE_THAT_FAILS",
    ]
    events, errors = ingest_and_normalize(parser, lines)
    assert len(events) == 1
    assert len(errors) == 1
    assert events[0].event_type == EventType.AUTHENTICATION_FAILURE
    assert events[0].source_ip == "192.0.2.15"
    assert errors[0].line_number == 2
