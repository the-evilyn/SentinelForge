"""Parser for Apache and Nginx Combined Log Format telemetry."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from engine.ingestion.base import BaseParser, ParsedRecord

# Apache Combined Log Format regex:
# %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
COMBINED_LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+(HTTP/[0-9.]+))?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)


class ApacheLogParser(BaseParser):
    """Parses Apache Combined Log Format records."""

    @property
    def format_name(self) -> str:
        return "apache_combined"

    def _parse_timestamp(self, ts_str: str) -> str:
        """Parse Apache timestamp '08/Oct/2026:14:00:10 +0000' to ISO-8601 UTC string."""
        # e.g. "08/Oct/2026:14:00:10 +0000"
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    def parse_line(self, line: str, line_number: int = 1) -> ParsedRecord | None:
        clean = line.strip()
        if not clean:
            return None

        match = COMBINED_LOG_PATTERN.match(clean)
        if not match:
            raise ValueError(f"Line does not match Apache Combined Log format: '{clean[:60]}...'")

        (
            client_ip,
            remote_user,
            raw_time,
            method,
            uri,
            protocol,
            status_code,
            bytes_sent,
            referer,
            user_agent,
        ) = match.groups()

        timestamp_iso = self._parse_timestamp(raw_time)

        extracted = {
            "timestamp": timestamp_iso,
            "src_ip": client_ip,
            "remote_user": None if remote_user == "-" else remote_user,
            "method": method,
            "uri": uri,
            "protocol": protocol or "HTTP/1.1",
            "status_code": int(status_code),
            "bytes_sent": 0 if bytes_sent == "-" else int(bytes_sent),
            "referer": referer or "",
            "user_agent": user_agent or "",
        }

        return ParsedRecord(
            source_format=self.format_name,
            raw_data=extracted,
            raw_log=clean,
            line_number=line_number,
        )
