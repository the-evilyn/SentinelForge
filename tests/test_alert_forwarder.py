"""Unit tests for the Wazuh alert forwarder.

These cover the pure logic (parsing, severity mapping, filtering, formatting)
with no network and no running Wazuh manager, so they run anywhere in <1s.
"""
import json
from pathlib import Path

import alert_forwarder as af
import pytest

SAMPLE_ALERT = json.dumps(
    {
        "timestamp": "2026-06-25T10:15:00+0000",
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: Multiple authentication failures.",
            "groups": ["syslog", "sshd", "authentication_failures"],
        },
        "agent": {"name": "web-01"},
        "data": {"srcip": "203.0.113.7"},
    }
)


def test_parse_alert_extracts_fields():
    alert = af.parse_alert(SAMPLE_ALERT)
    assert alert is not None
    assert alert.rule_id == "5712"
    assert alert.level == 10
    assert alert.agent == "web-01"
    assert alert.src_ip == "203.0.113.7"
    assert "sshd" in alert.groups


@pytest.mark.parametrize("line", ["", "   ", "not json", "{}", '{"foo": 1}'])
def test_parse_alert_skips_non_alerts(line):
    assert af.parse_alert(line) is None


@pytest.mark.parametrize(
    "level,expected",
    [(15, "critical"), (12, "critical"), (9, "high"), (6, "medium"), (2, "low"), (0, "low")],
)
def test_severity_band(level, expected):
    assert af.severity_band(level)[0] == expected


def test_should_forward_respects_threshold():
    alert = af.parse_alert(SAMPLE_ALERT)
    assert af.should_forward(alert, min_level=8) is True
    assert af.should_forward(alert, min_level=11) is False


def test_format_slack_message_shape():
    alert = af.parse_alert(SAMPLE_ALERT)
    payload = af.format_slack_message(alert)
    attachment = payload["attachments"][0]
    assert attachment["color"] == "#d83b01"  # high band
    assert "Multiple authentication failures" in attachment["title"]
    titles = {f["title"] for f in attachment["fields"]}
    assert {"Agent", "Rule", "Level", "Source IP"}.issubset(titles)


def test_format_slack_message_without_src_ip():
    record = json.loads(SAMPLE_ALERT)
    record["data"] = {}
    alert = af.parse_alert(json.dumps(record))
    payload = af.format_slack_message(alert)
    titles = {f["title"] for f in payload["attachments"][0]["fields"]}
    assert "Source IP" not in titles


def test_run_dry_run_counts_filtered(tmp_path: Path, capsys):
    # Two alerts: one above threshold, one below.
    low = json.dumps({"rule": {"id": "1", "level": 3, "description": "noise"}, "agent": {"name": "a"}})
    alerts = tmp_path / "alerts.json"
    alerts.write_text(SAMPLE_ALERT + "\n" + low + "\n", encoding="utf-8")

    sent = af.run(alerts, webhook_url=None, min_level=8, follow=False, dry_run=True)

    assert sent == 1
    out = capsys.readouterr().out
    assert "Multiple authentication failures" in out
