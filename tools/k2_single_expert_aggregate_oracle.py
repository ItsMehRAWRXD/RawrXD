#!/usr/bin/env python3
"""Single-routed-expert completed GPU aggregate vs independent scalar oracle.

Only one routed expert can be unambiguously attributed from a fused aggregate.
Even then the GPU post-SwiGLU and unweighted GPU down buffers are NOT captured:
this is a diagnostic weighted aggregate comparison, not G05/G06 certification.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from k2_aggregate_vector_audit import read_capture, compare
from k2_scalar_input_audit import evaluate


def audit(aggregate_manifest, scalar_manifest, max_abs, max_rms):
    aggregate = read_capture(Path(aggregate_manifest))
    if len(aggregate["experts"]) != 1:
        raise ValueError("MULTI_EXPERT_AGGREGATE_UNATTRIBUTABLE")
    meta, hashes, scalar = evaluate(Path(scalar_manifest))
    expert_id, route = aggregate["experts"][0]
    if ((aggregate["layer"], aggregate["stick"], expert_id) !=
            (meta["layer"], meta["stick"], meta["expert"])):
        raise ValueError("LAYER_STICK_EXPERT_IDENTITY_MISMATCH")
    if aggregate["rows"] != meta["hidden_dim"]:
        raise ValueError("HIDDEN_DIMENSION_MISMATCH")
    if not math.isfinite(route):
        raise ValueError("INVALID_ROUTING_WEIGHT")
    weighted_oracle = [float(route) * value for value in scalar["down"]]
    if not all(math.isfinite(value) for value in weighted_oracle):
        raise ValueError("NONFINITE_WEIGHTED_ORACLE")
    # compare() is the existing finite full-vector absolute/RMS comparator.
    record = dict(aggregate)
    record["vectors"] = {
        "gpu": aggregate["vectors"]["gpu"],
        "cpu": weighted_oracle,
    }
    metrics = compare(record, max_abs, max_rms)
    oracle_bytes = "".join(f"{v:.17g}\n" for v in weighted_oracle).encode("utf-8")
    receipt = {
        "schema": "DEEP2_KIMI_SINGLE_EXPERT_AGGREGATE_ORACLE_001/v1",
        "status": "PASS_DIAGNOSTIC" if metrics["within_threshold"] else "FAIL",
        "certified": False, "promote": 0,
        "gpu_post_swiglu_witness": "ABSENT",
        "gpu_unweighted_down_witness": "ABSENT",
        "scope": "SINGLE_EXPERT_ROUTED_AGGREGATE_VS_INDEPENDENT_SCALAR",
        "identity": {
            "layer": meta["layer"], "stick": meta["stick"],
            "expert": expert_id, "router_weight": route,
            "hidden_dim": meta["hidden_dim"],
            "intermediate_dim": meta["intermediate_dim"],
        },
        "aggregate_sha256": aggregate["sha256"],
        "scalar_input_sha256": hashes,
        "weighted_oracle_sha256": hashlib.sha256(oracle_bytes).hexdigest(),
        "thresholds": {"max_abs": max_abs, "max_rms": max_rms},
        "metrics": metrics,
        "note": "Single expert aggregate is weighted; no GPU per-stage output ownership proven",
    }
    return receipt


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--aggregate-manifest", type=Path, required=True)
    p.add_argument("--scalar-input-manifest", type=Path, required=True)
    p.add_argument("--max-abs", type=float, required=True)
    p.add_argument("--max-rms", type=float, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    args = p.parse_args(argv)
    if args.receipt.exists():
        print("ERROR: refusing to overwrite existing receipt")
        return 3
    try:
        result = audit(args.aggregate_manifest, args.scalar_input_manifest,
                       args.max_abs, args.max_rms)
        rc = 0 if result["status"] == "PASS_DIAGNOSTIC" else 2
    except (ValueError, OSError, UnicodeError, OverflowError) as exc:
        result = {
            "schema": "DEEP2_KIMI_SINGLE_EXPERT_AGGREGATE_ORACLE_001/v1",
            "status": "ERROR", "certified": False, "promote": 0,
            "gpu_post_swiglu_witness": "ABSENT",
            "gpu_unweighted_down_witness": "ABSENT", "error": str(exc),
        }
        rc = 3
    try:
        with args.receipt.open("x", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError as exc:
        print("ERROR: cannot create receipt:", exc)
        return 3
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
