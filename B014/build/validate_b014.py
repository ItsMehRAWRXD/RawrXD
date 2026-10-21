#!/usr/bin/env python3
"""B014 Evidence Validator — Numerical cross-check of JSON export against raw records."""

import json
import sys
from pathlib import Path

def validate_b014(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    invocations = data["invocations"]
    summary = data["summary"]
    layer_aggs = data["layer_aggregates"]
    op_type_aggs = data["op_type_aggregates"]

    errors = []
    warnings = []

    # ── 1. Summary totals must match raw record sums ──
    total_ns = sum(r["total_ms"] for r in invocations)
    dequant_ns = sum(r["dequant_ms"] for r in invocations)
    dot_ns = sum(r["dot_ms"] for r in invocations)
    overhead_ns = sum(r["overhead_ms"] for r in invocations)
    acq_ns = sum(r["acq_ms"] for r in invocations)

    if abs(total_ns - summary["total_ms"]) > 0.01:
        errors.append(f"summary.total_ms mismatch: {summary['total_ms']:.3f} vs sum {total_ns:.3f}")
    if abs(dequant_ns - (summary["dequant_pct"] * total_ns / 100.0)) > 0.1:
        warnings.append("dequant_pct may not reconcile with raw sum (expected for derived pct)")

    # ── 2. Layer aggregates must match raw records by layer ──
    layer_sums = {}
    for r in invocations:
        lid = r["layer_index"]
        layer_sums.setdefault(lid, {"count": 0, "total_ms": 0.0})
        layer_sums[lid]["count"] += 1
        layer_sums[lid]["total_ms"] += r["total_ms"]

    for agg in layer_aggs:
        lid = agg["layer_index"]
        if lid not in layer_sums:
            errors.append(f"layer_index {lid} in aggregates but no raw invocations")
            continue
        expected = layer_sums[lid]
        if expected["count"] != agg["invocation_count"]:
            errors.append(f"layer {lid}: count {agg['invocation_count']} vs raw {expected['count']}")
        if abs(expected["total_ms"] - agg["total_ms"]) > 0.01:
            errors.append(f"layer {lid}: total_ms mismatch {agg['total_ms']:.3f} vs raw {expected['total_ms']:.3f}")

    # ── 3. Op-type aggregates must match raw records by op_type ──
    op_sums = {}
    for r in invocations:
        ot = r["op_type"]
        op_sums.setdefault(ot, {"count": 0, "total_ms": 0.0})
        op_sums[ot]["count"] += 1
        op_sums[ot]["total_ms"] += r["total_ms"]

    for agg in op_type_aggs:
        ot = agg["op_type"]
        if ot not in op_sums:
            errors.append(f"op_type '{ot}' in aggregates but no raw invocations")
            continue
        expected = op_sums[ot]
        if expected["count"] != agg["invocation_count"]:
            errors.append(f"op_type '{ot}': count {agg['invocation_count']} vs raw {expected['count']}")
        if abs(expected["total_ms"] - agg["total_ms"]) > 0.01:
            errors.append(f"op_type '{ot}': total_ms mismatch {agg['total_ms']:.3f} vs raw {expected['total_ms']:.3f}")

    # ── 4. Percentages must sum to ~100% ──
    pct_sum = summary["dequant_pct"] + summary["dot_pct"] + summary["overhead_pct"] + summary["acq_pct"]
    if abs(pct_sum - 100.0) > 0.1:
        errors.append(f"percentages sum to {pct_sum:.2f}, expected ~100%")

    # ── 5. Invocation count consistency ──
    if summary["total_invocations"] != len(invocations):
        errors.append(f"total_invocations {summary['total_invocations']} != len(invocations) {len(invocations)}")

    return {
        "invocation_count": len(invocations),
        "errors": errors,
        "warnings": warnings,
        "passed": len(errors) == 0,
    }

if __name__ == "__main__":
    json_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("B014/logs/B014_compute_profile.json")
    if not json_path.exists():
        print(f"FAIL: JSON not found at {json_path}")
        sys.exit(1)

    result = validate_b014(json_path)
    print(f"B014 Evidence Validation Report")
    print(f"================================")
    print(f"JSON path:      {json_path}")
    print(f"Invocations:    {result['invocation_count']}")
    print(f"Errors:         {len(result['errors'])}")
    print(f"Warnings:       {len(result['warnings'])}")
    print()
    if result["errors"]:
        print("ERRORS:")
        for e in result["errors"]:
            print(f"  - {e}")
    if result["warnings"]:
        print("WARNINGS:")
        for w in result["warnings"]:
            print(f"  - {w}")
    print()
    status = "PASS" if result["passed"] else "FAIL"
    print(f"STATUS: {status}")
    sys.exit(0 if result["passed"] else 1)
