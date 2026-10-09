"""Parser for Suricata EVE JSON telemetry lines."""
from __future__ import annotations

import json
from typing import Any

from engine.ingestion.base import BaseParser, ParsedRecord
from engine.models import ensure_utc, format_iso_utc


class SuricataEveParser(BaseParser):
    """Parses Suricata Extensible Event Format (EVE) JSON lines."""

    @property
    def format_name(self) -> str:
        return "suricata_eve"

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

        if "timestamp" not in record or "event_type" not in record:
            raise ValueError(f"Missing required Suricata keys (timestamp/event_type) on line {line_number}")

        # Normalize timestamp to UTC ISO string
        utc_dt = ensure_utc(record["timestamp"])
        timestamp_iso = format_iso_utc(utc_dt)

        extracted = {
            "timestamp": timestamp_iso,
            "event_type": record.get("event_type"),
            "flow_id": record.get("flow_id"),
            "in_iface": record.get("in_iface"),
            "src_ip": record.get("src_ip"),
            "src_port": record.get("src_port"),
            "dest_ip": record.get("dest_ip"),
            "dest_port": record.get("dest_port"),
            "proto": record.get("proto"),
            "alert": record.get("alert"),
            "http": record.get("http"),
            "flow": record.get("flow"),
        }

        return ParsedRecord(
            source_format=self.format_name,
            raw_data=extracted,
            raw_log=clean,
            line_number=line_number,
        )
