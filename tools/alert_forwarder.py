#!/usr/bin/env python3
"""Forward high-severity Wazuh alerts to a chat webhook (Slack / Teams / generic).

Wazuh writes alerts as newline-delimited JSON to
``/var/ossec/logs/alerts/alerts.json``. This tool tails that file, keeps only
alerts at or above a chosen rule level, formats them, and POSTs them to an
incoming webhook so a small team gets actionable notifications without standing
up a full ticketing stack.

Design note: parsing, severity mapping, filtering and formatting are pure
functions with no I/O, so they are unit-tested without a network or a running
Wazuh manager. Only ``forward_alert`` touches the network.

Standard library only — no third-party dependencies.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# Wazuh rule levels run 0-15. These thresholds drive labelling/colour only.
SEVERITY_BANDS = (
    (12, "critical", "#b80000"),
    (8, "high", "#d83b01"),
    (5, "medium", "#f2c744"),
    (0, "low", "#36a64f"),
)


@dataclass(frozen=True)
class Alert:
    """A normalised view of the Wazuh fields we care about."""

    timestamp: str
    rule_id: str
    level: int
    description: str
    agent: str
    groups: tuple[str, ...]
    src_ip: str | None = None

    @property
    def severity(self) -> str:
        return severity_band(self.level)[0]

    @property
    def colour(self) -> str:
        return severity_band(self.level)[1]


def severity_band(level: int) -> tuple[str, str]:
    """Map a numeric Wazuh level to a (label, colour) pair."""
    for threshold, label, colour in SEVERITY_BANDS:
        if level >= threshold:
            return label, colour
    return "low", "#36a64f"


def parse_alert(line: str) -> Alert | None:
    """Parse one JSON line from alerts.json into an Alert.

    Returns None for blank lines or records that are not security rule matches
    (e.g. malformed lines), so the caller can simply skip them.
    """
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None

    rule = record.get("rule")
    if not isinstance(rule, dict) or "level" not in rule:
        return None

    agent = record.get("agent", {})
    data = record.get("data", {})

    return Alert(
        timestamp=record.get("timestamp", ""),
        rule_id=str(rule.get("id", "?")),
        level=int(rule.get("level", 0)),
        description=str(rule.get("description", "(no description)")),
        agent=str(agent.get("name", "unknown")),
        groups=tuple(rule.get("groups", []) or ()),
        src_ip=data.get("srcip"),
    )


def should_forward(alert: Alert, min_level: int) -> bool:
    """True when an alert meets or exceeds the configured level."""
    return alert.level >= min_level


def format_slack_message(alert: Alert) -> dict:
    """Build a Slack-compatible attachment payload for an alert."""
    fields = [
        {"title": "Agent", "value": alert.agent, "short": True},
        {"title": "Rule", "value": alert.rule_id, "short": True},
        {"title": "Level", "value": f"{alert.level} ({alert.severity})", "short": True},
    ]
    if alert.src_ip:
        fields.append({"title": "Source IP", "value": alert.src_ip, "short": True})

    return {
        "attachments": [
            {
                "color": alert.colour,
                "title": f"[{alert.severity.upper()}] {alert.description}",
                "ts": alert.timestamp,
                "fields": fields,
                "footer": "SentinelForge • Wazuh",
            }
        ]
    }


def forward_alert(webhook_url: str, payload: dict, timeout: float = 10.0) -> int:
    """POST a JSON payload to the webhook; return the HTTP status code."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (trusted webhook)
        return response.status


def iter_lines(path: Path, follow: bool, poll_interval: float = 1.0) -> Iterator[str]:
    """Yield lines from a file. When follow=True, keep tailing like ``tail -f``."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        if follow:
            handle.seek(0, 2)  # jump to EOF so we only see new alerts
        while True:
            line = handle.readline()
            if line:
                yield line
            elif follow:
                time.sleep(poll_interval)
            else:
                return


def run(
    alerts_path: Path,
    webhook_url: str | None,
    min_level: int,
    follow: bool,
    dry_run: bool,
) -> int:
    """Stream alerts and forward those above the threshold. Returns count sent."""
    sent = 0
    for line in iter_lines(alerts_path, follow=follow):
        alert = parse_alert(line)
        if alert is None or not should_forward(alert, min_level):
            continue
        payload = format_slack_message(alert)
        if dry_run or not webhook_url:
            print(json.dumps(payload))
        else:
            try:
                status = forward_alert(webhook_url, payload)
                print(f"forwarded rule {alert.rule_id} (level {alert.level}) -> HTTP {status}")
            except urllib.error.URLError as exc:
                print(f"WARN: failed to forward rule {alert.rule_id}: {exc}", file=sys.stderr)
                continue
        sent += 1
    return sent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--alerts",
        type=Path,
        default=Path("/var/ossec/logs/alerts/alerts.json"),
        help="Path to the Wazuh alerts.json file.",
    )
    parser.add_argument(
        "--webhook-url",
        default=None,
        help="Incoming webhook URL (Slack/Teams). Omit with --dry-run to test.",
    )
    parser.add_argument(
        "--min-level",
        type=int,
        default=8,
        help="Minimum Wazuh rule level to forward (default: 8 = high).",
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help="Keep tailing the file for new alerts (like tail -f).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print payloads instead of POSTing them.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.dry_run and not args.webhook_url:
        print("error: provide --webhook-url or use --dry-run", file=sys.stderr)
        return 2
    if not args.alerts.exists():
        print(f"error: alerts file not found: {args.alerts}", file=sys.stderr)
        return 1
    count = run(args.alerts, args.webhook_url, args.min_level, args.follow, args.dry_run)
    print(f"done: {count} alert(s) processed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
