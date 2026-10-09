"""MITRE ATT&CK enterprise matrix taxonomy and coverage mapper."""
from __future__ import annotations

from engine.models import MITREAttack

# Bundled offline enterprise ATT&CK knowledge base
KNOWN_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1046": ("Network Service Discovery", "Discovery"),
}


class MITREMatrix:
    """Manages MITRE ATT&CK technique catalog and computes detection coverage."""

    @staticmethod
    def get_technique(technique_id: str, rationale: str = "") -> MITREAttack | None:
        """Retrieve a validated MITREAttack object by ID."""
        info = KNOWN_TECHNIQUES.get(technique_id)
        if not info:
            return None
        name, tactic = info
        return MITREAttack(
            technique_id=technique_id,
            technique_name=name,
            tactic=tactic,
            rationale=rationale,
        )

    @staticmethod
    def calculate_coverage(rules: list[Any]) -> dict[str, Any]:
        """Compute MITRE ATT&CK coverage report across a set of detection rules."""
        tactic_map: dict[str, list[dict[str, str]]] = {}
        seen_techniques: set[str] = set()

        for rule in rules:
            techs = getattr(rule, "mitre_techniques", [])
            for tech in techs:
                t_id = tech.technique_id
                if t_id not in seen_techniques:
                    seen_techniques.add(t_id)
                    tactic = tech.tactic
                    if tactic not in tactic_map:
                        tactic_map[tactic] = []
                    tactic_map[tactic].append({
                        "technique_id": t_id,
                        "technique_name": tech.technique_name,
                        "rule_id": getattr(rule, "rule_id", "unknown"),
                    })

        return {
            "total_techniques_covered": len(seen_techniques),
            "tactics_covered": list(tactic_map.keys()),
            "matrix": tactic_map,
        }
