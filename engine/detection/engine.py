"""Detection Engine orchestrating rule execution against normalized events."""
from __future__ import annotations

from collections.abc import Iterable

from engine.detection.rule import BaseRule
from engine.detection.rules import (
    SSHBruteForceRule,
    WebDirectoryTraversalRule,
    WebSQLInjectionRule,
)
from engine.models import Alert, Event


class DetectionEngine:
    """Orchestrates detection rule evaluation over streams of normalized events."""

    def __init__(self, auto_load_defaults: bool = True) -> None:
        self._rules: dict[str, BaseRule] = {}
        if auto_load_defaults:
            self.load_default_rules()

    def register_rule(self, rule: BaseRule) -> None:
        """Register a detection rule into the engine."""
        self._rules[rule.rule_id] = rule

    def load_default_rules(self) -> None:
        """Load default SentinelForge detection rules."""
        self.register_rule(SSHBruteForceRule())
        self.register_rule(WebSQLInjectionRule())
        self.register_rule(WebDirectoryTraversalRule())

    def get_rule(self, rule_id: str) -> BaseRule | None:
        return self._rules.get(rule_id)

    @property
    def rules(self) -> list[BaseRule]:
        return list(self._rules.values())

    def process_event(self, event: Event) -> list[Alert]:
        """Evaluate an event against all registered rules, collecting generated alerts."""
        alerts: list[Alert] = []
        for rule in self._rules.values():
            try:
                alert = rule.evaluate(event)
                if alert is not None:
                    alerts.append(alert)
            except Exception as exc:
                # Log or handle rule execution failure gracefully
                continue
        return alerts

    def process_stream(self, events: Iterable[Event]) -> list[Alert]:
        """Process an iterable of events and collect all generated alerts in sequence."""
        all_alerts: list[Alert] = []
        for event in events:
            all_alerts.extend(self.process_event(event))
        return all_alerts

    def reset_state(self) -> None:
        """Reset stateful rules (e.g. counters, sliding windows)."""
        for rule in self._rules.values():
            if hasattr(rule, "reset_state"):
                rule.reset_state()
