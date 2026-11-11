#!/usr/bin/env python3
"""Independent multi-expert Kimi aggregate oracle; diagnostic-only, no GPU certification."""
import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from k2_aggregate_vector_audit import read_capture, compare
from k2_scalar_input_audit import evaluate

RUN_ID = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")


def audit(aggregate_manifest, scalar_directory, max_abs, max_rms):
    agg = read_capture(Path(aggregate_manifest))
    run_id = agg["run_id"]
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ValueError("AGGREGATE_RUN_ID_MISSING_OR_INVALID")
    if not 1 <= len(agg["experts"]) <= 8:
        raise ValueError("EXPERT_COUNT_OUTSIDE_CAPTURE_BOUNDS")
    if not scalar_directory.is_dir():
        raise ValueError("SCALAR_DIRECTORY_MISSING")
    rows = agg["rows"]
    total = [0.0] * rows
    input_hashes = {}
    for expert_id, weight in agg["experts"]:
        if not math.isfinite(weight):
            raise ValueError("NONFINITE_ROUTER_WEIGHT")
        manifest = scalar_directory / (
            f"k2_l{agg['layer']}_e{expert_id}_s{agg['stick']}_scalar_inputs.manifest.txt")
        meta, hashes, vectors = evaluate(manifest)
        if (meta["layer"] != agg["layer"] or
                meta["stick"] != agg["stick"] or
                meta["expert"] != expert_id or
                meta["hidden_dim"] != rows or meta.get("run_id") != run_id):
            raise ValueError("EXPERT_INPUT_IDENTITY_OR_RUN_MISMATCH")
        if len(vectors["down"]) != rows:
            raise ValueError("EXPERT_OUTPUT_DIMENSION_MISMATCH")
        for idx, value in enumerate(vectors["down"]):
            total[idx] += weight * value
            if not math.isfinite(total[idx]):
                raise ValueError("NONFINITE_SCALAR_AGGREGATE")
        input_hashes[str(expert_id)] = hashes
    comparisons = {}
    for name, left, right in (
        ("gpu_vs_oracle", agg["vectors"]["gpu"], total),
        ("cpu_vs_oracle", agg["vectors"]["cpu"], total),
        ("gpu_vs_cpu", agg["vectors"]["gpu"], agg["vectors"]["cpu"]),
    ):
        comparisons[name] = compare(
            {"rows": rows, "vectors": {"gpu": left, "cpu": right}},
            max_abs, max_rms)
    passed = all(m["within_threshold"] for m in comparisons.values())
    oracle_bytes = "".join(f"{v:.17g}\n" for v in total).encode("utf-8")
    return {
        "schema": "DEEP2_KIMI_ALL_EXPERT_AGGREGATE_ORACLE_001/v1",
        "status": "PASS_DIAGNOSTIC" if passed else "FAIL",
        "certified": False, "promote": 0, "gpu_expert_witness": "ABSENT",
        "scope": "COMPLETED_AGGREGATE_VS_ALL_SCALAR_EXPERTS",
        "identity": {
            "layer": agg["layer"], "stick": agg["stick"],
            "run_id": run_id, "rows": rows,
            "experts": agg["experts"],
        },
        "input_sha256": input_hashes,
        "aggregate_sha256": agg["sha256"],
        "oracle_sha256": hashlib.sha256(oracle_bytes).hexdigest(),
        "checks": {name: metric["within_threshold"]
                   for name, metric in comparisons.items()},
        "comparisons": comparisons,
        "thresholds": {"max_abs": max_abs, "max_rms": max_rms},
        "note": "All host-visible scalar inputs required; GPU output is aggregate, not per-expert",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--aggregate-manifest", required=True, type=Path)
    p.add_argument("--scalar-dir", required=True, type=Path)
    p.add_argument("--max-abs", required=True, type=float)
    p.add_argument("--max-rms", required=True, type=float)
    p.add_argument("--receipt", required=True, type=Path)
    a = p.parse_args(argv)
    if a.receipt.exists():
        print("ERROR: refusing to overwrite prior receipt")
        return 3
    try:
        result = audit(a.aggregate_manifest, a.scalar_dir, a.max_abs, a.max_rms)
        rc = 0 if result["status"] == "PASS_DIAGNOSTIC" else 2
    except (OSError, ValueError, OverflowError, UnicodeError) as exc:
        result = {
            "schema": "DEEP2_KIMI_ALL_EXPERT_AGGREGATE_ORACLE_001/v1",
            "status": "ERROR", "certified": False, "promote": 0,
            "gpu_expert_witness": "ABSENT", "error": str(exc),
        }
        rc = 3
    try:
        with a.receipt.open("x", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError as exc:
        print("ERROR: receipt write failed:", exc)
        return 3
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
