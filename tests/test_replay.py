"""Unit tests for offline replay and detection benchmark engine."""
from __future__ import annotations

from pathlib import Path

import pytest
from engine.evaluation.replay import ReplayEngine
from engine.ingestion import ApacheLogParser, AuthLogParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_replay_file_ssh_auth():
    engine = ReplayEngine()
    parser = AuthLogParser(default_year=2026)
    result = engine.replay_file(FIXTURES_DIR / "ssh_auth.log", parser)

    assert result.total_events >= 10
    assert result.alert_count >= 1
    assert result.incident_count >= 1

    # Verify high-severity incident was generated
    severities = {inc.severity.value for inc in result.incidents_generated}
    assert "critical" in severities or "high" in severities


def test_replay_file_apache_access():
    engine = ReplayEngine()
    parser = ApacheLogParser()
    result = engine.replay_file(FIXTURES_DIR / "apache_access.log", parser)

    assert result.total_events >= 6
    assert result.alert_count >= 1
    assert result.incident_count >= 1


def test_evaluate_benchmark_synthetic_scenarios():
    engine = ReplayEngine()
    metrics = engine.evaluate_benchmark(FIXTURES_DIR / "synthetic_events.json")

    assert metrics.total_scenarios == 4
    assert metrics.true_positives == 2
    assert metrics.false_positives == 0
    assert metrics.true_negatives == 2
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.false_positive_rate == 0.0
