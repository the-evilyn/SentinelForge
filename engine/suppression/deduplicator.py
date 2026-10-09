"""Alert deduplication, false-positive suppression, and allowlist filtering."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from engine.models import Alert


class AlertDeduplicator:
    """Manages alert deduplication windows and benign false-positive allowlists."""

    def __init__(
        self,
        suppression_window_seconds: int = 60,
        allowed_ips: dict[str, str] | None = None,
        allowed_users: dict[str, str] | None = None,
    ) -> None:
        self.suppression_window_seconds = suppression_window_seconds
        # Mapping: IP -> reason
        self.allowed_ips = allowed_ips or {"127.0.0.1": "Local healthcheck probe"}
        # Mapping: Username -> reason
        self.allowed_users = allowed_users or {"backup_svc": "Authorized backup automation"}

        # Key: (rule_id, source_ip, target_host) -> timestamp of last forwarded alert
        self._last_alert_time: dict[tuple[str, str | None, str | None], datetime] = {}
        # Repeated count tracking per key
        self._suppressed_counts: dict[tuple[str, str | None, str | None], int] = {}

        self.total_evaluated = 0
        self.forwarded_count = 0
        self.suppressed_count = 0
        self.allowlisted_count = 0

    def should_forward(self, alert: Alert) -> tuple[bool, str]:
        """Determine if an alert should be forwarded or suppressed.

        Returns:
            tuple (should_forward: bool, decision_reason: str)
        """
        self.total_evaluated += 1

        # 1. Check Allowlisted IPs
        if alert.source_ip and alert.source_ip in self.allowed_ips:
            reason = f"Allowlisted source IP {alert.source_ip}: {self.allowed_ips[alert.source_ip]}"
            self.allowlisted_count += 1
            return False, reason

        # 2. Check Allowlisted Users
        if alert.target_user and alert.target_user in self.allowed_users:
            reason = f"Allowlisted user {alert.target_user}: {self.allowed_users[alert.target_user]}"
            self.allowlisted_count += 1
            return False, reason

        # 3. Check Deduplication Window
        dedup_key = (alert.rule_id, alert.source_ip, alert.target_host)
        last_time = self._last_alert_time.get(dedup_key)

        if last_time is not None:
            time_since_last = alert.timestamp.timestamp() - last_time.timestamp()
            if 0 <= time_since_last < self.suppression_window_seconds:
                self.suppressed_count += 1
                self._suppressed_counts[dedup_key] = self._suppressed_counts.get(dedup_key, 0) + 1
                count = self._suppressed_counts[dedup_key]
                return False, f"Suppressed duplicate alert {alert.rule_id} (count={count}) within {self.suppression_window_seconds}s window"

        # Not suppressed: update tracker
        self._last_alert_time[dedup_key] = alert.timestamp
        self._suppressed_counts[dedup_key] = 0
        self.forwarded_count += 1
        return True, "Forward: passed deduplication and allowlist criteria"

    def reset_state(self) -> None:
        self._last_alert_time.clear()
        self._suppressed_counts.clear()
        self.total_evaluated = 0
        self.forwarded_count = 0
        self.suppressed_count = 0
        self.allowlisted_count = 0
