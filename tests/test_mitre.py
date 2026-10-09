"""Unit tests for MITREMatrix ATT&CK taxonomy and coverage calculations."""
from __future__ import annotations

import pytest
from engine.detection.engine import DetectionEngine
from engine.mitre.matrix import MITREMatrix


def test_mitre_matrix_lookup():
    tech = MITREMatrix.get_technique("T1110.001", rationale="SSH brute force")
    assert tech is not None
    assert tech.technique_id == "T1110.001"
    assert tech.technique_name == "Password Guessing"
    assert tech.tactic == "Credential Access"
    assert "https://attack.mitre.org/techniques/T1110/001/" in tech.url

    assert MITREMatrix.get_technique("T9999.999") is None


def test_mitre_coverage_calculation():
    engine = DetectionEngine()
    coverage = MITREMatrix.calculate_coverage(engine.rules)

    assert coverage["total_techniques_covered"] >= 2
    assert "Credential Access" in coverage["tactics_covered"]
    assert "Initial Access" in coverage["tactics_covered"]
