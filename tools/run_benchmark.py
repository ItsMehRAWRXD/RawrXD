#!/usr/bin/env python3
"""
run_benchmark.py

Headless Day 9 benchmark generator for SafetyInterceptor overhead gates.
Produces JSON compatible with tools/perf_budget_gate.py.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List, TypedDict


class BenchmarkRow(TypedDict):
    mode: str
    elapsedMs: float
    processedTokens: int
    tokensPerSec: float
    violationCount: int
    blockedCount: int
    overheadPct: float


def build_benchmark_tokens() -> List[str]:
    # Mirrors frontend benchmark corpus, including split-secret and split-restricted patterns.
    corpus = [
        "plain text ",
        "normal code ",
        "email: ",
        "alice@example.com ",
        "start key ",
        "sk-",
        "12345678901234567890 ",
        "aws ",
        "AKIA",
        "ABCD1234EFGH5678 ",
        "github ",
        "ghp_",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ ",
        "danger ",
        "os.",
        "system(",
        '"echo hi") ',
        "tail ",
    ]

    out: List[str] = []
    for _ in range(1200):
        out.extend(corpus)
    return out


def detect_violations(window: str) -> Dict[str, bool]:
    # Deterministic checks aligned with the main safety ruleset.
    has_secret = (
        "sk-12345678901234567890" in window
        or "AKIAABCD1234EFGH5678" in window
        or "ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" in window
    )
    has_pii = "alice@example.com" in window
    has_restricted = "os.system(" in window
    return {
        "secret": has_secret,
        "pii": has_pii,
        "restricted": has_restricted,
    }


def run_mode(tokens: List[str], loops: int, mode: str) -> BenchmarkRow:
    look_behind = ""
    window_size = 50
    processed = 0
    violations = 0
    blocked = 0

    start = time.perf_counter()

    for _ in range(loops):
        look_behind = ""
        for token in tokens:
            processed += 1
            window = look_behind + token
            flags = detect_violations(window)
            has_violation = flags["secret"] or flags["pii"] or flags["restricted"]

            out_token = token
            if has_violation:
                violations += 1
                if mode == "BLOCK":
                    out_token = "[STREAM_BLOCKED:RESTRICTED]"
                    blocked += 1
                elif mode == "REDACT":
                    # Keep replacement deterministic and lightweight for CI overhead estimation.
                    out_token = "[REDACTED]"

            look_behind = (look_behind + out_token)[-window_size:]

            if mode == "BLOCK" and blocked > 0:
                # Mirror runtime stream termination semantics.
                break

    elapsed_ms = max(0.001, (time.perf_counter() - start) * 1000.0)
    tps = processed / (elapsed_ms / 1000.0)

    return {
        "mode": mode,
        "elapsedMs": elapsed_ms,
        "processedTokens": processed,
        "tokensPerSec": tps,
        "violationCount": violations,
        "blockedCount": blocked,
        "overheadPct": 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run headless safety benchmark and export JSON")
    parser.add_argument("--output", required=True, type=Path, help="Output JSON path")
    parser.add_argument("--loops", default=8, type=int, help="Loop count per mode (default: 8)")
    parser.add_argument("--headless", action="store_true", help="Compatibility flag; no-op")
    args = parser.parse_args()

    tokens = build_benchmark_tokens()
    baseline_count = args.loops * len(tokens)

    # Baseline append-only cost.
    sink = ""
    baseline_start = time.perf_counter()
    for _ in range(args.loops):
        for tok in tokens:
            sink += tok
    if len(sink) == -1:  # impossible, prevents dead-code elimination assumptions
        print("unreachable")
    baseline_elapsed_ms = max(0.001, (time.perf_counter() - baseline_start) * 1000.0)
    baseline_ns_per_token = (baseline_elapsed_ms * 1_000_000.0) / baseline_count

    rows: List[BenchmarkRow] = [
        {
            "mode": "BASELINE",
            "elapsedMs": baseline_elapsed_ms,
            "processedTokens": baseline_count,
            "tokensPerSec": baseline_count / (baseline_elapsed_ms / 1000.0),
            "violationCount": 0,
            "blockedCount": 0,
            "overheadPct": 0.0,
        },
        run_mode(tokens, args.loops, "PASSTHROUGH"),
        run_mode(tokens, args.loops, "REDACT"),
        run_mode(tokens, args.loops, "BLOCK"),
    ]

    for row in rows[1:]:
        ns_per_token = (row["elapsedMs"] * 1_000_000.0) / max(1, row["processedTokens"])
        row["overheadPct"] = ((ns_per_token - baseline_ns_per_token) / baseline_ns_per_token) * 100.0

    payload: Dict[str, Any] = {
        "schemaVersion": "day8.safety-benchmark.v1",
        "generatedAtEpochMs": int(time.time() * 1000),
        "loops": args.loops,
        "rows": rows,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Benchmark written: {args.output}")
    for row in rows:
        print(
            f"{row['mode']}: tps={row['tokensPerSec']:.2f}, "
            f"overhead={row['overheadPct']:.2f}%, blocked={row['blockedCount']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
