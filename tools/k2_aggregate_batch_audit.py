#!/usr/bin/env python3
"""Aggregate MoE numerical coverage audit across selected layer/stick pairs.

Input is a private capture directory with exact post-device paired manifests.
All requested scopes must exist and satisfy frozen absolute/RMS thresholds.
This does not certify individual GPU experts or GPU activation ownership.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from k2_aggregate_vector_audit import compare, read_capture


def audit(directory, required, max_abs, max_rms):
    if not directory.is_dir():
        raise ValueError("capture directory does not exist")
    if not required or len(required) > 512:
        raise ValueError("required layer/stick scopes must be bounded and nonempty")
    if len(required) != len(set(required)):
        raise ValueError("duplicate required layer/stick scope")
    if not all(math.isfinite(v) and v >= 0 for v in (max_abs, max_rms)):
        raise ValueError("invalid thresholds")

    entries = []
    for layer, stick in required:
        if layer < 0 or stick not in (0, 1):
            raise ValueError("invalid layer/stick scope")
        path = directory / f"k2_l{layer}_s{stick}_aggregate_comparison.manifest.txt"
        try:
            capture = read_capture(path)
            if capture["layer"] != layer or capture["stick"] != stick:
                raise ValueError("capture scope mismatch")
            metrics = compare(capture, max_abs, max_rms)
            status = "PASS_DIAGNOSTIC" if metrics["within_threshold"] else "FAIL"
            entry = {
                "layer": layer, "stick": stick, "status": status,
                "expert_ids": [expert for expert, _ in capture["experts"]],
                "routing_weights": [weight for _, weight in capture["experts"]],
                "sha256": capture["sha256"],
                "metrics": metrics,
            }
        except (ValueError, OSError, UnicodeError, OverflowError) as exc:
            entry = {"layer": layer, "stick": stick, "status": "ERROR",
                     "error": str(exc)}
        entries.append(entry)
    counts = {
        "pass": sum(e["status"] == "PASS_DIAGNOSTIC" for e in entries),
        "fail": sum(e["status"] == "FAIL" for e in entries),
        "error": sum(e["status"] == "ERROR" for e in entries),
    }
    status = ("PASS_DIAGNOSTIC" if counts["pass"] == len(entries) else
              "ERROR" if counts["error"] else "FAIL")
    return {
        "schema": "DEEP2_KIMI_AGGREGATE_BATCH_001/v1",
        "status": status,
        "certified": False,
        "promote": 0,
        "gpu_expert_witness": "ABSENT",
        "scope": "COMPLETED_AGGREGATE_DIAGNOSTIC_ONLY",
        "required_scopes": len(required),
        "counts": counts,
        "thresholds": {"max_abs": max_abs, "max_rms": max_rms},
        "entries": entries,
        "note": "All requested pairs must pass; no per-expert GPU proof",
    }


def parse_scope(token):
    parts = token.split(":")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        raise ValueError("required scope must be LAYER:STICK")
    return int(parts[0]), int(parts[1])


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--capture-dir", required=True, type=Path)
    p.add_argument("--require", required=True, nargs="+", metavar="LAYER:STICK")
    p.add_argument("--max-abs", required=True, type=float)
    p.add_argument("--max-rms", required=True, type=float)
    p.add_argument("--receipt", required=True, type=Path)
    args = p.parse_args(argv)
    if args.receipt.exists():
        print("ERROR: refusing to overwrite existing receipt")
        return 3
    try:
        scopes = [parse_scope(s) for s in args.require]
        result = audit(args.capture_dir, scopes, args.max_abs, args.max_rms)
        code = 0 if result["status"] == "PASS_DIAGNOSTIC" else (
            3 if result["status"] == "ERROR" else 2)
    except (OSError, ValueError, OverflowError, UnicodeError) as exc:
        result = {"schema": "DEEP2_KIMI_AGGREGATE_BATCH_001/v1",
                  "status": "ERROR", "certified": False, "promote": 0,
                  "gpu_expert_witness": "ABSENT", "error": str(exc)}
        code = 3
    try:
        with args.receipt.open("x", encoding="utf-8") as out:
            json.dump(result, out, indent=2, sort_keys=True)
            out.write("\n")
    except OSError as exc:
        print("ERROR: cannot write receipt:", exc)
        return 3
    print(result["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
