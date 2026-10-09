"""Offline telemetry replay engine and detection quality evaluation."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engine.correlation.correlator import EventCorrelator
from engine.detection.engine import DetectionEngine
from engine.ingestion.base import BaseParser
from engine.models import Alert, Event, Incident
from engine.normalization.normalizer import EventNormalizer


@dataclass
class ReplayResult:
    """Output summary of an offline replay run."""

    total_events: int
    alerts_generated: list[Alert] = field(default_factory=list)
    incidents_generated: list[Incident] = field(default_factory=list)

    @property
    def alert_count(self) -> int:
        return len(self.alerts_generated)

    @property
    def incident_count(self) -> int:
        return len(self.incidents_generated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total_events,
            "alert_count": self.alert_count,
            "incident_count": self.incident_count,
            "alerts": [a.to_dict() for a in self.alerts_generated],
            "incidents": [i.to_dict() for i in self.incidents_generated],
        }


@dataclass
class EvaluationMetrics:
    """Detection performance metrics on labeled benchmark datasets."""

    total_scenarios: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_scenarios": self.total_scenarios,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


class ReplayEngine:
    """Offline telemetry runner that benchmarks detection and correlation algorithms."""

    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        correlator: EventCorrelator | None = None,
    ) -> None:
        self.detector = detection_engine or DetectionEngine()
        self.correlator = correlator or EventCorrelator()

    def replay_events(self, events: list[Event]) -> ReplayResult:
        """Process a sequence of pre-normalized events through detection and correlation."""
        self.detector.reset_state()
        self.correlator.reset_state()

        collected_alerts: list[Alert] = []
        collected_incidents: list[Incident] = []

        for event in events:
            alerts = self.detector.process_event(event)
            collected_alerts.extend(alerts)
            incidents = self.correlator.process(event, alerts)
            for inc in incidents:
                if inc not in collected_incidents:
                    collected_incidents.append(inc)

        return ReplayResult(
            total_events=len(events),
            alerts_generated=collected_alerts,
            incidents_generated=collected_incidents,
        )

    def replay_file(self, file_path: Path | str, parser: BaseParser) -> ReplayResult:
        """Parse raw telemetry file, normalize, and process through the full pipeline."""
        ingest_res = parser.parse_file(file_path)
        normalizer = EventNormalizer()
        events = normalizer.normalize_batch(ingest_res.records)
        return self.replay_events(events)

    def evaluate_benchmark(self, scenarios_path: Path | str) -> EvaluationMetrics:
        """Run labeled scenario benchmarks and compute detection precision and recall."""
        path = Path(scenarios_path)
        data = json.loads(path.read_text(encoding="utf-8"))

        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for scenario in data:
            expected_class = scenario.get("classification", "benign")
            raw_events = scenario.get("events", [])
            events = [Event.from_dict(e) for e in raw_events]

            res = self.replay_events(events)
            has_alert = res.alert_count > 0 or res.incident_count > 0

            if expected_class == "malicious":
                if has_alert:
                    tp += 1
                else:
                    fn += 1
            else:  # benign
                if has_alert:
                    fp += 1
                else:
                    tn += 1

        total = tp + fp + tn + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return EvaluationMetrics(
            total_scenarios=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate=fpr,
        )
