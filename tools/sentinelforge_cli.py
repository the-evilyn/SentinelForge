#!/usr/bin/env python3
"""SentinelForge CLI — Command-line interface for offline detection, replay, and reporting."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine.detection.engine import DetectionEngine
from engine.evaluation.replay import ReplayEngine
from engine.ingestion import (
    ApacheLogParser,
    AuthLogParser,
    SuricataEveParser,
    WazuhAlertsParser,
)
from engine.reporting.reporter import IncidentReporter


def get_parser_by_name(format_name: str):
    parsers = {
        "linux_auth": AuthLogParser(),
        "apache_combined": ApacheLogParser(),
        "suricata_eve": SuricataEveParser(),
        "wazuh_alert": WazuhAlertsParser(),
    }
    return parsers.get(format_name)


def cmd_replay(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    parser = get_parser_by_name(args.format)
    if not parser:
        print(f"Error: unknown format '{args.format}'. Choose from linux_auth, apache_combined, suricata_eve, wazuh_alert", file=sys.stderr)
        return 1

    engine = ReplayEngine()
    result = engine.replay_file(path, parser)

    print(f"=== SentinelForge Offline Replay Summary ===")
    print(f"File: {path.name} | Format: {args.format}")
    print(f"Total Events Processed: {result.total_events}")
    print(f"Alerts Generated:       {result.alert_count}")
    print(f"Incidents Correlated:   {result.incident_count}")

    if result.alerts_generated:
        print("\n--- Alerts ---")
        for alt in result.alerts_generated:
            print(f"[{alt.severity.value.upper()}] {alt.rule_id} - {alt.summary} (Score: {alt.risk_score.score})")

    if result.incidents_generated:
        print("\n--- Incidents ---")
        for inc in result.incidents_generated:
            print(f"[{inc.severity.value.upper()}] {inc.incident_id} - {inc.title} (Risk: {inc.risk_score.score}/100)")

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"\nSaved replay report to: {out_path}")

    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    path = Path(args.scenarios)
    if not path.is_file():
        print(f"Error: scenario file not found: {path}", file=sys.stderr)
        return 1

    engine = ReplayEngine()
    metrics = engine.evaluate_benchmark(path)

    print("=== SentinelForge Benchmark Evaluation ===")
    print(f"Scenarios Evaluated: {metrics.total_scenarios}")
    print(f"True Positives:      {metrics.true_positives}")
    print(f"False Positives:     {metrics.false_positives}")
    print(f"True Negatives:      {metrics.true_negatives}")
    print(f"False Negatives:     {metrics.false_negatives}")
    print(f"Precision:           {metrics.precision:.2%}")
    print(f"Recall:              {metrics.recall:.2%}")
    print(f"F1 Score:            {metrics.f1_score:.2%}")
    print(f"False Positive Rate: {metrics.false_positive_rate:.2%}")

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(metrics.to_dict(), indent=2), encoding="utf-8")
        print(f"\nSaved benchmark metrics to: {out_path}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelforge",
        description="SentinelForge — SOC Detection & Incident Response Engine",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Replay
    replay_p = subparsers.add_parser("replay", help="Replay a raw telemetry file through the engine")
    replay_p.add_argument("--file", "-f", required=True, help="Path to telemetry file")
    replay_p.add_argument("--format", "-m", required=True, choices=["linux_auth", "apache_combined", "suricata_eve", "wazuh_alert"], help="Telemetry format")
    replay_p.add_argument("--output", "-o", help="Optional output path for JSON report")

    # Benchmark
    bench_p = subparsers.add_parser("benchmark", help="Evaluate detection metrics on labeled scenarios")
    bench_p.add_argument("--scenarios", "-s", required=True, help="Path to synthetic_events.json")
    bench_p.add_argument("--output", "-o", help="Optional output path for metrics JSON")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "replay":
        return cmd_replay(args)
    elif args.command == "benchmark":
        return cmd_benchmark(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
