"""Unit tests for RiskScorer transparent multi-factor scoring model."""
from __future__ import annotations

import pytest
from engine.models import Severity
from engine.scoring.scorer import RiskScorer


def test_scorer_base_severity_scaling():
    scorer = RiskScorer()

    score_low = scorer.compute_score(Severity.LOW, confidence=1.0)
    score_crit = scorer.compute_score(Severity.CRITICAL, confidence=1.0)

    assert score_low.score < score_crit.score
    assert score_crit.score >= 90.0
    assert score_low.severity == Severity.LOW
    assert score_crit.severity == Severity.CRITICAL


def test_scorer_confidence_weighting():
    scorer = RiskScorer()

    score_high_conf = scorer.compute_score(Severity.HIGH, confidence=1.0)
    score_low_conf = scorer.compute_score(Severity.HIGH, confidence=0.2)

    assert score_high_conf.score > score_low_conf.score


def test_scorer_frequency_logarithmic_dampening():
    scorer = RiskScorer()

    score_10 = scorer.compute_score(Severity.MEDIUM, confidence=0.8, event_count=10)
    score_1000 = scorer.compute_score(Severity.MEDIUM, confidence=0.8, event_count=1000)

    # Log scaling ensures massive event counts cannot infinitely explode the score
    assert score_1000.factors["frequency_boost"] <= 15.0
    assert score_1000.score <= 100.0


def test_scorer_sequence_boost_and_explanation():
    scorer = RiskScorer()

    single_score = scorer.compute_score(Severity.HIGH, confidence=0.85, is_correlated_sequence=False)
    seq_score = scorer.compute_score(Severity.HIGH, confidence=0.85, is_correlated_sequence=True)

    assert seq_score.score == single_score.score + 15.0
    assert "Multi-stage attack sequence escalation" in seq_score.rationale
    assert "base_severity" in seq_score.factors
    assert "correlation_sequence_boost" in seq_score.factors
