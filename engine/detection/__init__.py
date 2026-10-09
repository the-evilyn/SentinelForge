"""Detection package for SentinelForge."""
from __future__ import annotations

from engine.detection.engine import DetectionEngine
from engine.detection.rule import BaseRule

__all__ = ["BaseRule", "DetectionEngine"]
