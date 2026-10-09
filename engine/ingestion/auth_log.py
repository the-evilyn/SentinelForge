"""Parser for Linux /var/log/auth.log (Syslog RFC 3164 with sshd telemetry)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from engine.ingestion.base import BaseParser, ParsedRecord

# Standard RFC 3164 Syslog header: "Oct 08 14:00:01 web-01 sshd[28101]: "
SYSLOG_HEADER_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([a-zA-Z0-9_\-]+)(?:\[(\d+)\])?:\s+(.*)$"
)

# SSH Event patterns
FAILED_INVALID_PATTERN = re.compile(
    r"^Failed password for invalid user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)\s+ssh2"
)
FAILED_USER_PATTERN = re.compile(
    r"^Failed password for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)\s+ssh2"
)
ACCEPTED_PWD_PATTERN = re.compile(
    r"^Accepted password for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)\s+ssh2"
)
ACCEPTED_PUBKEY_PATTERN = re.compile(
    r"^Accepted publickey for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)\s+ssh2(?::\s+(.*))?"
)


class AuthLogParser(BaseParser):
    """Parses Linux auth.log / sshd authentication events."""

    def __init__(self, default_year: int | None = None) -> None:
        self.default_year = default_year or datetime.now(timezone.utc).year

    @property
    def format_name(self) -> str:
        return "linux_auth"

    def _parse_timestamp(self, ts_str: str) -> str:
        """Parse BSD syslog timestamp like 'Oct 08 14:00:01' and return ISO-8601 UTC string."""
        dt = datetime.strptime(f"{self.default_year} {ts_str}", "%Y %b %d %H:%M:%S")
        dt_utc = dt.replace(tzinfo=timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    def parse_line(self, line: str, line_number: int = 1) -> ParsedRecord | None:
        clean = line.strip()
        if not clean:
            return None

        match = SYSLOG_HEADER_PATTERN.match(clean)
        if not match:
            raise ValueError(f"Line does not match RFC 3164 syslog format: '{clean[:60]}...'")

        ts_raw, hostname, process, pid, message = match.groups()
        timestamp_iso = self._parse_timestamp(ts_raw)

        extracted: dict[str, str | int | None] = {
            "timestamp": timestamp_iso,
            "host": hostname,
            "process": process,
            "pid": int(pid) if pid else None,
            "action": "unknown",
            "user": None,
            "src_ip": None,
            "src_port": None,
            "auth_method": None,
            "is_invalid_user": False,
        }

        # Match specific SSH message variants
        m_fail_inv = FAILED_INVALID_PATTERN.match(message)
        if m_fail_inv:
            user, src_ip, port = m_fail_inv.groups()
            extracted.update({
                "action": "login_failed",
                "user": user,
                "src_ip": src_ip,
                "src_port": int(port),
                "auth_method": "password",
                "is_invalid_user": True,
            })
            return ParsedRecord(source_format=self.format_name, raw_data=extracted, raw_log=clean, line_number=line_number)

        m_fail = FAILED_USER_PATTERN.match(message)
        if m_fail:
            user, src_ip, port = m_fail.groups()
            extracted.update({
                "action": "login_failed",
                "user": user,
                "src_ip": src_ip,
                "src_port": int(port),
                "auth_method": "password",
                "is_invalid_user": False,
            })
            return ParsedRecord(source_format=self.format_name, raw_data=extracted, raw_log=clean, line_number=line_number)

        m_acc_pwd = ACCEPTED_PWD_PATTERN.match(message)
        if m_acc_pwd:
            user, src_ip, port = m_acc_pwd.groups()
            extracted.update({
                "action": "login_success",
                "user": user,
                "src_ip": src_ip,
                "src_port": int(port),
                "auth_method": "password",
                "is_invalid_user": False,
            })
            return ParsedRecord(source_format=self.format_name, raw_data=extracted, raw_log=clean, line_number=line_number)

        m_acc_pubkey = ACCEPTED_PUBKEY_PATTERN.match(message)
        if m_acc_pubkey:
            user, src_ip, port, key_info = m_acc_pubkey.groups()
            extracted.update({
                "action": "login_success",
                "user": user,
                "src_ip": src_ip,
                "src_port": int(port),
                "auth_method": "publickey",
                "key_info": key_info,
                "is_invalid_user": False,
            })
            return ParsedRecord(source_format=self.format_name, raw_data=extracted, raw_log=clean, line_number=line_number)

        # Unrecognized message inside syslog
        extracted["message"] = message
        return ParsedRecord(source_format=self.format_name, raw_data=extracted, raw_log=clean, line_number=line_number)
