"""Rule DET-WEB-001: SQL Injection Detection."""
from __future__ import annotations

import re
import urllib.parse

from engine.detection.rule import BaseRule
from engine.models import Alert, Event, EventType, MITREAttack, Severity

SQLI_PATTERNS = [
    # UNION SELECT queries
    re.compile(r"(?i)\bunion\s+(?:all\s+)?select\b"),
    # Boolean tautology: ' OR '1'='1 or 1=1
    re.compile(r"(?i)(?:'|\")\s*(?:or|and)\s*(?:'|\")?\w+(?:'|\")?\s*=\s*(?:'|\")?\w+"),
    # Database metadata probing
    re.compile(r"(?i)\b(?:information_schema|pg_catalog|sys\.databases)\b"),
    # Time-based blind payloads: sleep(5), benchmark(1000000)
    re.compile(r"(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d+\s*\)"),
]


class WebSQLInjectionRule(BaseRule):
    """Detects common SQL injection indicators in HTTP request URIs and query parameters."""

    rule_id = "DET-WEB-001"
    rule_name = "SQL Injection Indicators in Web Request"
    description = "Detects SQL injection payload patterns in HTTP query strings and URIs."
    severity = Severity.HIGH
    base_score = 70.0
    confidence = 0.80

    mitre_techniques = [
        MITREAttack(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            rationale="Adversary injecting SQL commands to bypass authentication or extract backend database records.",
        )
    ]

    def evaluate(self, event: Event) -> Alert | None:
        if event.event_type != EventType.WEB_REQUEST:
            return None

        uri = str(event.metadata.get("uri", ""))
        if not uri:
            # Fallback to inspecting raw log
            uri = event.raw_log

        # Decode URL query strings to evaluate raw payloads
        decoded_uri = urllib.parse.unquote_plus(uri)

        matched_patterns = []
        for pat in SQLI_PATTERNS:
            if pat.search(decoded_uri):
                matched_patterns.append(pat.pattern)

        if matched_patterns:
            summary = (
                f"SQL injection attempt detected from {event.source_ip or 'unknown'}: "
                f"matched pattern in request URI."
            )
            factors = {
                "base_severity": self.base_score,
                "confidence_weight": self.confidence * 15.0,
                "pattern_count_boost": float(len(matched_patterns) * 5),
            }
            return self.create_alert(
                event=event,
                summary=summary,
                custom_factors=factors,
                extra_metadata={"matched_patterns": matched_patterns, "inspected_uri": decoded_uri[:200]},
            )

        return None
