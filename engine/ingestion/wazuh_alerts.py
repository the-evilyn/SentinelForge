"""Parser for Wazuh alerts.json telemetry lines."""
from __future__ import annotations

import json
from typing import Any

from engine.ingestion.base import BaseParser, ParsedRecord
from engine.models import ensure_utc, format_iso_utc


class WazuhAlertsParser(BaseParser):
    """Parses Wazuh alerts.json newline-delimited JSON records."""

    @property
    def format_name(self) -> str:
        return "wazuh_alert"

    def parse_line(self, line: str, line_number: int = 1) -> ParsedRecord | None:
        clean = line.strip()
        if not clean:
            return None

        try:
            record: dict[str, Any] = json.loads(clean)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON on line {line_number}: {exc}") from exc

        if not isinstance(record, dict):
            raise ValueError(f"Expected JSON object on line {line_number}, got {type(record).__name__}")

        rule = record.get("rule")
        if not isinstance(rule, dict) or "id" not in rule or "level" not in rule:
            raise ValueError(f"Record on line {line_number} is not a valid Wazuh security alert")

        raw_ts = record.get("timestamp")
        timestamp_iso = format_iso_utc(ensure_utc(raw_ts)) if raw_ts else ""

        agent = record.get("agent", {})
        data = record.get("data", {})

        extracted = {
            "timestamp": timestamp_iso,
            "rule_id": str(rule.get("id")),
            "level": int(rule.get("level", 0)),
            "description": str(rule.get("description", "")),
            "groups": list(rule.get("groups", []) or []),
            "agent_name": str(agent.get("name", "unknown")),
            "agent_id": str(agent.get("id", "")),
            "src_ip": data.get("srcip"),
            "src_port": data.get("srcport"),
            "dst_ip": data.get("dstip"),
            "dst_port": data.get("dstport"),
            "full_log": record.get("full_log", ""),
            "mitre": rule.get("mitre", {}),
        }

        return ParsedRecord(
            source_format=self.format_name,
            raw_data=extracted,
            raw_log=clean,
            line_number=line_number,
        )
