"""Base parser interfaces and data structures for telemetry ingestion.

Enforces clear separation between raw parsing and semantic normalization.
Tracks line-level errors, records malformed lines, and produces structured
records without crashing the pipeline.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ParsedRecord:
    """Intermediate structured representation of a parsed raw log line."""

    source_format: str
    raw_data: dict[str, Any]
    raw_log: str
    line_number: int = 1


@dataclass(frozen=True)
class ParseError:
    """Record of an unparseable or malformed telemetry entry."""

    line_number: int
    raw_line: str
    error_message: str


@dataclass
class IngestionResult:
    """Summary and payload of a batch or file parsing run."""

    records: list[ParsedRecord] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)
    total_lines: int = 0

    @property
    def success_count(self) -> int:
        return len(self.records)

    @property
    def error_count(self) -> int:
        return len(self.errors)


class BaseParser(ABC):
    """Abstract base class for format-specific log parsers."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Name of the format handled by this parser."""
        ...

    @abstractmethod
    def parse_line(self, line: str, line_number: int = 1) -> ParsedRecord | None:
        """Parse a single log line into a ParsedRecord.

        Returns None if the line is empty or purely whitespace.
        Raises ValueError or appropriate exception on malformed content.
        """
        ...

    def parse_stream(self, lines: Iterable[str]) -> IngestionResult:
        """Parse an iterable of log lines, accumulating records and recording errors."""
        result = IngestionResult()
        for idx, line in enumerate(lines, start=1):
            result.total_lines += 1
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = self.parse_line(line, line_number=idx)
                if record is not None:
                    result.records.append(record)
            except Exception as exc:
                result.errors.append(
                    ParseError(
                        line_number=idx,
                        raw_line=line.rstrip("\r\n"),
                        error_message=str(exc),
                    )
                )
        return result

    def parse_file(self, file_path: Path | str) -> IngestionResult:
        """Read and parse an entire log file from disk."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Telemetry file not found: {path}")
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return self.parse_stream(f)
