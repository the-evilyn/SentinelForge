"""Explainable risk scoring model for SentinelForge detections and incidents."""
from __future__ import annotations

import math
from typing import Any

from engine.models import RiskScore, Severity


class RiskScorer:
    """Transparent, deterministic multi-factor risk calculator."""

    MODEL_VERSION = "1.0.0"

    SEVERITY_BASE_SCORES = {
        Severity.INFORMATIONAL: 10.0,
        Severity.LOW: 25.0,
        Severity.MEDIUM: 50.0,
        Severity.HIGH: 75.0,
        Severity.CRITICAL: 90.0,
    }

    def compute_score(
        self,
        severity: Severity,
        confidence: float,
        event_count: int = 1,
        is_correlated_sequence: bool = False,
        asset_exposure: str = "internal",  # "internal" or "external"
        rationale_prefix: str = "",
    ) -> RiskScore:
        """Calculate an explainable RiskScore with bounded factor contributions.

        Formula:
          Score = (BaseSeverity * ConfidenceWeight) + FrequencyFactor + SequenceBoost + ExposureBoost
          Bounded to [0.0, 100.0].
        """
        base_sev = self.SEVERITY_BASE_SCORES.get(severity, 50.0)
        conf = max(0.0, min(1.0, confidence))

        # 1. Base component scaled by confidence
        base_weighted = round(base_sev * (0.6 + 0.4 * conf), 1)

        # 2. Dampened frequency boost: log scale prevents runaway scores
        freq_factor = 0.0
        if event_count > 1:
            freq_factor = round(min(15.0, 3.5 * math.log(event_count + 1)), 1)

        # 3. Correlation sequence boost
        sequence_boost = 15.0 if is_correlated_sequence else 0.0

        # 4. Exposure boost
        exposure_boost = 5.0 if asset_exposure.lower() == "external" else 0.0

        # Sum and bound
        raw_total = base_weighted + freq_factor + sequence_boost + exposure_boost
        final_score = round(min(100.0, max(0.0, raw_total)), 1)
        final_severity = Severity.from_score(final_score)

        factors = {
            "base_severity": base_weighted,
            "frequency_boost": freq_factor,
            "correlation_sequence_boost": sequence_boost,
            "asset_exposure_boost": exposure_boost,
        }

        # Build human-readable explanation
        reasons = [
            f"Base severity '{severity.value}' weighted by confidence {conf:.2f} ({base_weighted} pts)"
        ]
        if freq_factor > 0:
            reasons.append(f"Frequency factor for {event_count} events (+{freq_factor} pts)")
        if sequence_boost > 0:
            reasons.append(f"Multi-stage attack sequence escalation (+{sequence_boost} pts)")
        if exposure_boost > 0:
            reasons.append(f"External asset exposure (+{exposure_boost} pts)")

        explanation = f"{rationale_prefix} Risk Score {final_score:.1f}/100 [v{self.MODEL_VERSION}]: " + "; ".join(reasons) + "."

        return RiskScore(
            score=final_score,
            severity=final_severity,
            confidence=conf,
            factors=factors,
            rationale=explanation,
        )
