"""Ingestion package for SentinelForge.

Provides parsers for Linux authentication logs, Apache access logs,
Suricata EVE JSON, and Wazuh alert streams.
"""
from __future__ import annotations

from engine.ingestion.apache_log import ApacheLogParser
from engine.ingestion.auth_log import AuthLogParser
from engine.ingestion.base import BaseParser, IngestionResult, ParseError, ParsedRecord
from engine.ingestion.suricata_eve import SuricataEveParser
from engine.ingestion.wazuh_alerts import WazuhAlertsParser

__all__ = [
    "ApacheLogParser",
    "AuthLogParser",
    "BaseParser",
    "IngestionResult",
    "ParseError",
    "ParsedRecord",
    "SuricataEveParser",
    "WazuhAlertsParser",
]
