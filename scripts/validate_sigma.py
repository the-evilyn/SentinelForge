#!/usr/bin/env python3
"""Lightweight structural validator for the Sigma rules in detections/sigma/.

Not a full Sigma compiler (that's `sigma-cli`'s job) — this catches the common
authoring mistakes (missing keys, bad level, duplicate IDs) fast in CI without
pulling a heavy dependency tree. Run: python scripts/validate_sigma.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REQUIRED_TOP_KEYS = {"title", "id", "description", "logsource", "detection", "level"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
RULES_DIR = Path(__file__).resolve().parent.parent / "detections" / "sigma"


def validate_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]

    if not isinstance(doc, dict):
        return ["top-level document is not a mapping"]

    missing = REQUIRED_TOP_KEYS - doc.keys()
    if missing:
        errors.append(f"missing keys: {', '.join(sorted(missing))}")

    level = doc.get("level")
    if level is not None and level not in VALID_LEVELS:
        errors.append(f"invalid level '{level}' (allowed: {', '.join(sorted(VALID_LEVELS))})")

    detection = doc.get("detection")
    if isinstance(detection, dict) and "condition" not in detection:
        errors.append("detection block has no 'condition'")

    return errors


def main() -> int:
    files = sorted(RULES_DIR.glob("*.yml"))
    if not files:
        print(f"no Sigma rules found in {RULES_DIR}", file=sys.stderr)
        return 1

    seen_ids: dict[str, Path] = {}
    failed = False

    for path in files:
        errors = validate_file(path)
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict):
            rule_id = doc.get("id")
            if rule_id in seen_ids:
                errors.append(f"duplicate id, also used by {seen_ids[rule_id].name}")
            elif rule_id:
                seen_ids[rule_id] = path

        if errors:
            failed = True
            print(f"FAIL {path.name}")
            for err in errors:
                print(f"     - {err}")
        else:
            print(f"OK   {path.name}")

    print(f"\n{len(files)} rule(s) checked.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
