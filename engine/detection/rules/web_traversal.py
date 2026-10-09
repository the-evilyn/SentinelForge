"""Rule DET-WEB-002: Directory Traversal Detection."""
from __future__ import annotations

import re
import urllib.parse

from engine.detection.rule import BaseRule
from engine.models import Alert, Event, EventType, MITREAttack, Severity

TRAVERSAL_PATTERNS = [
    re.compile(r"(?:\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e\/)", re.IGNORECASE),
    re.compile(r"(?:/etc/passwd|/etc/shadow|/windows/win\.ini|boot\.ini)", re.IGNORECASE),
]


class WebDirectoryTraversalRule(BaseRule):
    """Detects path traversal sequences attempting unauthorized file system access."""

    rule_id = "DET-WEB-002"
    rule_name = "Directory Traversal Pattern in Web Request"
    description = "Detects directory traversal sequences attempting unauthorized file access."
    severity = Severity.MEDIUM
    base_score = 55.0
    confidence = 0.85

    mitre_techniques = [
        MITREAttack(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            rationale="Adversary utilizing path traversal sequences to access sensitive operating system files.",
        )
    ]

    def evaluate(self, event: Event) -> Alert | None:
        if event.event_type != EventType.WEB_REQUEST:
            return None

        uri = str(event.metadata.get("uri", "")) or event.raw_log
        decoded_uri = urllib.parse.unquote_plus(uri)

        matched = []
        for pat in TRAVERSAL_PATTERNS:
            if pat.search(decoded_uri):
                matched.append(pat.pattern)

        if matched:
            summary = (
                f"Directory traversal sequence detected from {event.source_ip or 'unknown'}: "
                f"attempting unauthorized file access."
            )
            factors = {
                "base_severity": self.base_score,
                "confidence_weight": self.confidence * 15.0,
            }
            return self.create_alert(
                event=event,
                summary=summary,
                custom_factors=factors,
                extra_metadata={"matched_patterns": matched, "inspected_uri": decoded_uri[:200]},
            )

        return None
