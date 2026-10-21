#!/usr/bin/env python3
"""B014 Resident vs Non-Resident Invocation Analyzer

Reads B014_compute_profile.json and compares invocations where b011_hit=True
(resident/cached) vs b011_hit=False (non-resident/streaming).

This answers the critical question:
> Does B011 select a different compute path, or does the same kernel become
> dramatically faster when operating on resident memory?
"""

import json
import sys
from pathlib import Path

def analyze_residency_impact(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    invocations = data["invocations"]

    resident = [r for r in invocations if r.get("b011_hit", False)]
    non_resident = [r for r in invocations if not r.get("b011_hit", False)]

    def stats(records):
        if not records:
            return {"count": 0, "mean_total_ms": 0, "mean_dequant_ms": 0, "mean_dot_ms": 0,
                    "mean_overhead_ms": 0, "mean_acq_ms": 0}
        n = len(records)
        return {
            "count": n,
            "mean_total_ms": sum(r["total_ms"] for r in records) / n,
            "mean_dequant_ms": sum(r["dequant_ms"] for r in records) / n,
            "mean_dot_ms": sum(r["dot_ms"] for r in records) / n,
            "mean_overhead_ms": sum(r["overhead_ms"] for r in records) / n,
            "mean_acq_ms": sum(r["acq_ms"] for r in records) / n,
        }

    r_stats = stats(resident)
    nr_stats = stats(non_resident)

    def ratio(a, b):
        if b == 0:
            return float('inf') if a > 0 else 0.0
        return a / b

    return {
        "resident": r_stats,
        "non_resident": nr_stats,
        "speedup_total": ratio(nr_stats["mean_total_ms"], r_stats["mean_total_ms"]),
        "speedup_dot": ratio(nr_stats["mean_dot_ms"], r_stats["mean_dot_ms"]),
        "speedup_dequant": ratio(nr_stats["mean_dequant_ms"], r_stats["mean_dequant_ms"]),
        "resident_count": len(resident),
        "non_resident_count": len(non_resident),
    }

if __name__ == "__main__":
    json_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("B014/logs/B014_compute_profile.json")
    if not json_path.exists():
        print(f"FAIL: JSON not found at {json_path}")
        sys.exit(1)

    result = analyze_residency_impact(json_path)

    print("=" * 70)
    print("B014 RESIDENT vs NON-RESIDENT ANALYSIS")
    print("=" * 70)
    print(f"JSON: {json_path}")
    print()
    print(f"Resident invocations     (b011_hit=True):  {result['resident_count']}")
    print(f"Non-resident invocations (b011_hit=False): {result['non_resident_count']}")
    print()

    r = result["resident"]
    nr = result["non_resident"]

    print("RESIDENT (cached) averages:")
    print(f"  Total:     {r['mean_total_ms']:.3f} ms")
    print(f"  Dot:       {r['mean_dot_ms']:.3f} ms")
    print(f"  Dequant:   {r['mean_dequant_ms']:.3f} ms")
    print(f"  Overhead:  {r['mean_overhead_ms']:.3f} ms")
    print(f"  Acq:       {r['mean_acq_ms']:.3f} ms")
    print()

    print("NON-RESIDENT (streaming) averages:")
    print(f"  Total:     {nr['mean_total_ms']:.3f} ms")
    print(f"  Dot:       {nr['mean_dot_ms']:.3f} ms")
    print(f"  Dequant:   {nr['mean_dequant_ms']:.3f} ms")
    print(f"  Overhead:  {nr['mean_overhead_ms']:.3f} ms")
    print(f"  Acq:       {nr['mean_acq_ms']:.3f} ms")
    print()

    print("SPEEDUP (non-resident / resident):")
    print(f"  Total:     {result['speedup_total']:.2f}x")
    print(f"  Dot:       {result['speedup_dot']:.2f}x")
    print(f"  Dequant:   {result['speedup_dequant']:.2f}x")
    print()

    if result['resident_count'] > 0 and result['non_resident_count'] > 0:
        print("INTERPRETATION:")
        if result['speedup_dot'] > 2.0:
            print("  → Dot-product is substantially faster on resident memory.")
            print("  → Likely cause: cache locality / L2-L3 affinity / aligned layout.")
        elif result['speedup_dot'] < 1.2:
            print("  → Dot-product time is similar regardless of residency.")
            print("  → The speedup comes from eliminated acquisition/dequant overhead.")
        else:
            print("  → Moderate dot-product improvement from residency.")

        if result['speedup_dequant'] > 2.0:
            print("  → Dequantization also benefits from residency (pre-packed format).")
        elif result['speedup_dequant'] < 1.0:
            print("  → Dequantization is SLOWER on resident path (unexpected).")
    else:
        print("WARNING: Need both resident and non-resident invocations for comparison.")
        print("         Run with B011 residency toggled mid-workload or use a cold-start model.")

    print("=" * 70)
