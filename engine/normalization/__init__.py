"""Normalization package for SentinelForge.

Provides canonical EventNormalizer and pipeline helper functions.
"""
from __future__ import annotations

from engine.normalization.normalizer import EventNormalizer, ingest_and_normalize

__all__ = ["EventNormalizer", "ingest_and_normalize"]
