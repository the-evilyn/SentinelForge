"""Detection rules catalog for SentinelForge."""
from __future__ import annotations

from engine.detection.rules.ssh_bruteforce import SSHBruteForceRule
from engine.detection.rules.web_sqli import WebSQLInjectionRule
from engine.detection.rules.web_traversal import WebDirectoryTraversalRule

__all__ = [
    "SSHBruteForceRule",
    "WebDirectoryTraversalRule",
    "WebSQLInjectionRule",
]
