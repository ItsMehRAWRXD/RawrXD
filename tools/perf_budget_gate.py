#!/usr/bin/env python3
"""
perf_budget_gate.py

Day 8 performance budget validator.
Consumes SafetyAuditPanel benchmark export JSON and enforces overhead limits.

Expected JSON schema (v1):
{
  "schemaVersion": "day8.safety-benchmark.v1",
  "generatedAtEpochMs": 1717280000000,
  "loops": 8,
  "rows": [
    { "mode": "BASELINE", ... },
    { "mode": "PASSTHROUGH", ... },
    { "mode": "REDACT", ... },
    { "mode": "BLOCK", ... }
  ]
}
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def _load_payload(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Failed to parse JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeError("Invalid benchmark payload: root is not an object")

    rows = data.get("rows")
    if not isinstance(rows, list):
        raise RuntimeError("Invalid benchmark payload: missing rows[]")

    return data


def _find_row(rows: List[Dict[str, Any]], mode: str) -> Optional[Dict[str, Any]]:
    for row in rows:
        if isinstance(row, dict) and str(row.get("mode", "")).upper() == mode.upper():
            return row
    return None


def _float_from_row(row: Dict[str, Any], key: str) -> float:
    value = row.get(key)
    if isinstance(value, (int, float)):
        return float(value)
    raise RuntimeError(f"Row for mode={row.get('mode')} missing numeric '{key}'")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate safety benchmark against performance budget")
    parser.add_argument("benchmark_json", nargs="?", type=Path, help="Path to exported benchmark JSON")
    parser.add_argument("--input", dest="benchmark_json_input", type=Path, help="Alias for benchmark JSON path")
    parser.add_argument(
        "--max-redact-overhead-pct",
        type=float,
        default=5.0,
        help="Maximum allowed REDACT overhead percentage versus baseline (default: 5.0)",
    )
    parser.add_argument(
        "--max-passthrough-overhead-pct",
        type=float,
        default=3.0,
        help="Maximum allowed PASSTHROUGH overhead percentage versus baseline (default: 3.0)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help=(
            "Compatibility budget flag applied to REDACT overhead. "
            "Accepts ratio (0.05 => 5%%) or percent (5 => 5%%)."
        ),
    )
    args = parser.parse_args()

    benchmark_path = args.benchmark_json_input or args.benchmark_json
    if benchmark_path is None:
        parser.error("benchmark_json is required (positional or --input)")

    if args.threshold is not None:
        threshold_pct = args.threshold * 100.0 if args.threshold <= 1.0 else args.threshold
        args.max_redact_overhead_pct = threshold_pct

    payload = _load_payload(benchmark_path)
    rows = payload["rows"]

    if not all(isinstance(r, dict) for r in rows):
        print("FAIL: rows[] must contain objects", file=sys.stderr)
        return 2

    baseline = _find_row(rows, "BASELINE")
    redact = _find_row(rows, "REDACT")
    passthrough = _find_row(rows, "PASSTHROUGH")

    if baseline is None or redact is None or passthrough is None:
        print("FAIL: required rows missing (BASELINE, PASSTHROUGH, REDACT)", file=sys.stderr)
        return 2

    # Prefer explicit overheadPct from the benchmark export.
    # Fallback formula if absent: overhead = ((baseline_tps / mode_tps) - 1) * 100
    def overhead(row: Dict[str, Any]) -> float:
        if isinstance(row.get("overheadPct"), (int, float)):
            return float(row["overheadPct"])
        baseline_tps = _float_from_row(baseline, "tokensPerSec")
        mode_tps = _float_from_row(row, "tokensPerSec")
        if mode_tps <= 0:
            raise RuntimeError(f"Invalid mode TPS for {row.get('mode')}: {mode_tps}")
        return ((baseline_tps / mode_tps) - 1.0) * 100.0

    redact_overhead = overhead(redact)
    passthrough_overhead = overhead(passthrough)

    print("Performance budget report")
    print(f"  benchmark: {benchmark_path}")
    print(f"  schema: {payload.get('schemaVersion', 'unknown')}")
    print(f"  PASSTHROUGH overhead: {passthrough_overhead:.2f}% (limit {args.max_passthrough_overhead_pct:.2f}%)")
    print(f"  REDACT overhead:      {redact_overhead:.2f}% (limit {args.max_redact_overhead_pct:.2f}%)")

    failed = False
    if passthrough_overhead > args.max_passthrough_overhead_pct:
        print("FAIL: PASSTHROUGH overhead budget exceeded", file=sys.stderr)
        failed = True
    if redact_overhead > args.max_redact_overhead_pct:
        print("FAIL: REDACT overhead budget exceeded", file=sys.stderr)
        failed = True

    if failed:
        return 1

    print("PASS: performance budgets satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
