"""Event normalization engine.

Transforms heterogeneous ParsedRecord instances into canonical, typed
engine.models.Event objects adhering to strict schema and timezone invariants.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from engine.ingestion.base import BaseParser, ParseError, ParsedRecord
from engine.models import Event, EventType, ensure_utc


class EventNormalizer:
    """Normalizes format-specific parsed records into standard Event models."""

    def normalize(self, record: ParsedRecord) -> Event:
        """Convert a single ParsedRecord into an Event instance.

        Raises:
            ValueError: If required normalization fields cannot be mapped.
        """
        data = record.raw_data
        fmt = record.source_format

        if fmt == "linux_auth":
            return self._normalize_linux_auth(data, record.raw_log)
        elif fmt == "apache_combined":
            return self._normalize_apache_combined(data, record.raw_log)
        elif fmt == "suricata_eve":
            return self._normalize_suricata_eve(data, record.raw_log)
        elif fmt == "wazuh_alert":
            return self._normalize_wazuh_alert(data, record.raw_log)
        else:
            return self._normalize_generic(data, record.raw_log, fmt)

    def normalize_batch(self, records: Iterable[ParsedRecord]) -> list[Event]:
        """Normalize an iterable of records, preserving order."""
        return [self.normalize(r) for r in records]

    def _normalize_linux_auth(self, data: dict, raw_log: str) -> Event:
        action = str(data.get("action", "unknown"))
        if action == "login_failed":
            event_type = EventType.AUTHENTICATION_FAILURE
        elif action == "login_success":
            event_type = EventType.AUTHENTICATION_SUCCESS
        else:
            event_type = EventType.GENERIC

        ts = ensure_utc(str(data.get("timestamp") or datetime.now(timezone.utc)))
        src_port = int(data["src_port"]) if data.get("src_port") is not None else None

        metadata = {
            "is_invalid_user": data.get("is_invalid_user", False),
            "auth_method": data.get("auth_method"),
            "process": data.get("process"),
            "pid": data.get("pid"),
        }
        if "key_info" in data and data["key_info"]:
            metadata["key_info"] = data["key_info"]

        return Event(
            event_type=event_type,
            timestamp=ts,
            source_ip=str(data["src_ip"]) if data.get("src_ip") else None,
            source_port=src_port,
            destination_port=22,
            user=str(data["user"]) if data.get("user") else None,
            host=str(data["host"]) if data.get("host") else None,
            service="sshd",
            action=action,
            raw_log=raw_log,
            metadata=metadata,
        )

    def _normalize_apache_combined(self, data: dict, raw_log: str) -> Event:
        ts = ensure_utc(str(data.get("timestamp") or datetime.now(timezone.utc)))
        method = str(data.get("method", "GET")).upper()
        action = f"http_{method.lower()}"

        metadata = {
            "uri": data.get("uri", ""),
            "method": method,
            "protocol": data.get("protocol", "HTTP/1.1"),
            "status_code": data.get("status_code", 0),
            "bytes_sent": data.get("bytes_sent", 0),
            "referer": data.get("referer", ""),
            "user_agent": data.get("user_agent", ""),
        }

        return Event(
            event_type=EventType.WEB_REQUEST,
            timestamp=ts,
            source_ip=str(data["src_ip"]) if data.get("src_ip") else None,
            destination_port=80,
            user=str(data["remote_user"]) if data.get("remote_user") else None,
            service="apache",
            action=action,
            raw_log=raw_log,
            metadata=metadata,
        )

    def _normalize_suricata_eve(self, data: dict, raw_log: str) -> Event:
        eve_type = data.get("event_type")
        if eve_type == "alert":
            event_type = EventType.NETWORK_ALERT
            action = "ids_alert"
        elif eve_type == "flow":
            event_type = EventType.NETWORK_FLOW
            action = "flow_summary"
        else:
            event_type = EventType.GENERIC
            action = str(eve_type or "network_event")

        ts = ensure_utc(str(data.get("timestamp") or datetime.now(timezone.utc)))

        src_port = int(data["src_port"]) if data.get("src_port") is not None else None
        dest_port = int(data["dest_port"]) if data.get("dest_port") is not None else None

        metadata = {
            "proto": data.get("proto"),
            "flow_id": data.get("flow_id"),
            "in_iface": data.get("in_iface"),
            "alert": data.get("alert"),
            "http": data.get("http"),
            "flow": data.get("flow"),
        }

        return Event(
            event_type=event_type,
            timestamp=ts,
            source_ip=str(data["src_ip"]) if data.get("src_ip") else None,
            source_port=src_port,
            destination_ip=str(data["dest_ip"]) if data.get("dest_ip") else None,
            destination_port=dest_port,
            service="suricata",
            action=action,
            raw_log=raw_log,
            metadata=metadata,
        )

    def _normalize_wazuh_alert(self, data: dict, raw_log: str) -> Event:
        groups = data.get("groups", [])
        if any("authentication_fail" in g for g in groups):
            event_type = EventType.AUTHENTICATION_FAILURE
        elif any("authentication_succ" in g for g in groups):
            event_type = EventType.AUTHENTICATION_SUCCESS
        else:
            event_type = EventType.GENERIC

        ts = ensure_utc(str(data.get("timestamp") or datetime.now(timezone.utc)))
        src_port = int(data["src_port"]) if data.get("src_port") is not None else None
        dst_port = int(data["dst_port"]) if data.get("dst_port") is not None else None

        metadata = {
            "rule_id": data.get("rule_id"),
            "level": data.get("level"),
            "groups": groups,
            "description": data.get("description"),
            "mitre": data.get("mitre"),
            "agent_id": data.get("agent_id"),
        }

        return Event(
            event_type=event_type,
            timestamp=ts,
            source_ip=str(data["src_ip"]) if data.get("src_ip") else None,
            source_port=src_port,
            destination_ip=str(data["dst_ip"]) if data.get("dst_ip") else None,
            destination_port=dst_port,
            host=str(data["agent_name"]) if data.get("agent_name") else None,
            service="wazuh",
            action=f"rule_{data.get('rule_id')}",
            raw_log=raw_log,
            metadata=metadata,
        )

    def _normalize_generic(self, data: dict, raw_log: str, source_format: str) -> Event:
        ts = ensure_utc(str(data.get("timestamp") or datetime.now(timezone.utc)))
        return Event(
            event_type=EventType.GENERIC,
            timestamp=ts,
            source_ip=str(data["src_ip"]) if data.get("src_ip") else None,
            host=str(data["host"]) if data.get("host") else None,
            service=source_format,
            action="generic_event",
            raw_log=raw_log,
            metadata=dict(data),
        )


def ingest_and_normalize(
    parser: BaseParser, lines: Iterable[str]
) -> tuple[list[Event], list[ParseError]]:
    """Convenience pipeline function to parse raw lines and normalize them.

    Returns:
        tuple containing (list_of_normalized_events, list_of_parse_errors).
    """
    result = parser.parse_stream(lines)
    normalizer = EventNormalizer()
    events = normalizer.normalize_batch(result.records)
    return events, result.errors
