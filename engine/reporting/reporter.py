"""Deterministic JSON and Markdown incident report generator."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from engine.models import Event, Incident, format_iso_utc


class IncidentReporter:
    """Generates auditable, deterministic incident reports in JSON and Markdown."""

    @staticmethod
    def calculate_evidence_hash(events: list[Event]) -> str:
        """Compute a SHA-256 integrity hash over chronological raw logs."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        concatenated = "\n".join(e.raw_log for e in sorted_events).encode("utf-8")
        return hashlib.sha256(concatenated).hexdigest()

    def generate_json_report(
        self, incident: Incident, evidence_events: list[Event] | None = None
    ) -> str:
        """Produce a deterministic, structured JSON report."""
        rep = incident.to_dict()
        rep["report_metadata"] = {
            "generated_at": format_iso_utc(datetime.now(timezone.utc)),
            "generator": "SentinelForge v1.0.0",
        }
        if evidence_events:
            rep["evidence_integrity"] = {
                "event_count": len(evidence_events),
                "sha256_hash": self.calculate_evidence_hash(evidence_events),
            }
        return json.dumps(rep, indent=2)

    def generate_markdown_report(
        self, incident: Incident, evidence_events: list[Event] | None = None
    ) -> str:
        """Produce a clean, publication-grade Markdown incident response report."""
        lines: list[str] = []
        lines.append(f"# Incident Report: {incident.incident_id}")
        lines.append("")
        lines.append(f"**Title:** {incident.title}  ")
        lines.append(f"**Severity:** `{incident.severity.value.upper()}` | **Status:** `{incident.status.value.upper()}`  ")
        lines.append(f"**Created:** {format_iso_utc(incident.created_at)} | **Updated:** {format_iso_utc(incident.updated_at)}  ")
        lines.append(f"**Source Identifier:** `{incident.source_ip or 'N/A'}`  ")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 1. Executive Summary & Risk Assessment")
        lines.append("")
        lines.append(f"- **Calculated Risk Score:** `{incident.risk_score.score}/100`")
        lines.append(f"- **Assessment Rationale:** {incident.risk_score.rationale}")
        lines.append("")
        lines.append("### Score Contributing Factors")
        lines.append("")
        lines.append("| Factor Component | Weight / Points |")
        lines.append("|:---|:---|")
        for factor_name, factor_val in incident.risk_score.factors.items():
            lines.append(f"| `{factor_name}` | `{factor_val:+.1f}` |")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 2. MITRE ATT&CK Mapping")
        lines.append("")
        if incident.mitre_techniques:
            lines.append("| Technique ID | Technique Name | Tactic | Reference |")
            lines.append("|:---|:---|:---|:---|")
            for tech in incident.mitre_techniques:
                url_str = f"[{tech.technique_id}]({tech.url})" if tech.url else tech.technique_id
                lines.append(f"| {url_str} | {tech.technique_name} | {tech.tactic} | {tech.rationale} |")
        else:
            lines.append("_No explicit ATT&CK techniques mapped._")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 3. Chronological Incident Timeline")
        lines.append("")
        if incident.timeline:
            lines.append("| Timestamp (UTC) | Rule ID | Severity | Event Summary |")
            lines.append("|:---|:---|:---|:---|")
            for entry in incident.timeline:
                lines.append(f"| {entry.get('timestamp')} | `{entry.get('rule_id')}` | `{entry.get('severity')}` | {entry.get('summary')} |")
        else:
            lines.append("_No timeline entries recorded._")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 4. Recommended Defensive Actions (NIST SP 800-61r2)")
        lines.append("")
        for idx, action in enumerate(incident.recommended_actions, 1):
            lines.append(f"{idx}. {action}")
        lines.append("")
        if evidence_events:
            lines.append("---")
            lines.append("")
            lines.append("## 5. Forensic Evidence Integrity")
            lines.append("")
            lines.append(f"- **Total Evidence Events:** `{len(evidence_events)}`")
            lines.append(f"- **SHA-256 Digest:** `{self.calculate_evidence_hash(evidence_events)}`")
            lines.append("- _Integrity Note: Hash computed over concatenated raw telemetry in chronological sequence._")
            lines.append("")

        return "\n".join(lines)
