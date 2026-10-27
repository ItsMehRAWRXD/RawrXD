#!/usr/bin/env python3
"""Fail-closed full-vector CPU/GPU/oracle parity receipt for Deep2 MoE.

Inputs are raw little-endian IEEE-754 float32 vectors exported from the SAME
expert, token, quantized weights, and routing state. This tool does not create
an oracle: --oracle must come from an independent scalar/dequantized path.
"""
import argparse
import hashlib
import json
import math
import os
import struct
import sys
from pathlib import Path


def load_f32(path):
    data = Path(path).read_bytes()
    if not data or len(data) % 4:
        raise ValueError(f"{path}: expected nonempty multiple-of-four f32le bytes")
    values = struct.unpack("<" + "f" * (len(data) // 4), data)
    if not all(math.isfinite(v) for v in values):
        raise ValueError(f"{path}: nonfinite vector element")
    return values, hashlib.sha256(data).hexdigest()


def metrics(actual, reference, zero_floor):
    if len(actual) != len(reference):
        raise ValueError("vector dimension mismatch")
    n = len(actual)
    differences = [float(a) - float(b) for a, b in zip(actual, reference)]
    abs_errors = [abs(x) for x in differences]
    max_index = max(range(n), key=lambda i: abs_errors[i])
    ref_norm_sq = math.fsum(float(v) * v for v in reference)
    act_norm_sq = math.fsum(float(v) * v for v in actual)
    dot = math.fsum(float(a) * float(b) for a, b in zip(actual, reference))
    if ref_norm_sq == 0 or act_norm_sq == 0:
        cosine = 1.0 if ref_norm_sq == act_norm_sq == 0 else 0.0
    else:
        cosine = max(-1.0, min(1.0, dot / math.sqrt(ref_norm_sq * act_norm_sq)))
    relative = [err / max(abs(float(b)), zero_floor)
                for err, b in zip(abs_errors, reference)]
    rms = math.sqrt(math.fsum(d * d for d in differences) / n)
    return {
        "elements": n,
        "max_abs": abs_errors[max_index],
        "max_abs_index": max_index,
        "reference_at_max": reference[max_index],
        "actual_at_max": actual[max_index],
        "mean_abs": math.fsum(abs_errors) / n,
        "rms_abs": rms,
        "rms_relative_to_reference": rms / max(math.sqrt(ref_norm_sq / n), zero_floor),
        "max_relative_floor": max(relative),
        "cosine_similarity": cosine,
        "reference_l2": math.sqrt(ref_norm_sq),
        "actual_l2": math.sqrt(act_norm_sq),
        "nonfinite_count": 0,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ("cpu", "gpu", "oracle"):
        p.add_argument("--" + flag, required=True, type=Path)
    p.add_argument("--expert-id", required=True, type=int)
    p.add_argument("--layer", required=True, type=int)
    p.add_argument("--token-step", required=True, type=int)
    p.add_argument("--input-sha256", required=True, help="SHA256 of common expert input")
    p.add_argument("--weights-sha256", required=True, help="SHA256 of common quantized weights")
    p.add_argument("--oracle-method", required=True,
                   help="Description of independently implemented oracle kernel")
    p.add_argument("--max-abs-tol", required=True, type=float)
    p.add_argument("--rms-tol", required=True, type=float)
    p.add_argument("--cos-min", required=True, type=float)
    p.add_argument("--relative-floor", type=float, default=1e-6)
    p.add_argument("--output", type=Path)
    args = p.parse_args(argv)
    try:
        if args.expert_id < 0 or args.layer < 0 or args.token_step < 0:
            raise ValueError("layer, expert-id, and token-step must be nonnegative")
        if any(not math.isfinite(v) for v in (args.max_abs_tol, args.rms_tol,
                                               args.cos_min, args.relative_floor)):
            raise ValueError("nonfinite tolerance")
        if args.max_abs_tol < 0 or args.rms_tol < 0 or args.relative_floor <= 0:
            raise ValueError("invalid nonnegative tolerance or relative floor")
        if not -1 <= args.cos_min <= 1:
            raise ValueError("cos-min must be between -1 and 1")
        for label, digest in (("input", args.input_sha256),
                              ("weights", args.weights_sha256)):
            if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
                raise ValueError(f"{label} SHA256 must be 64 hex characters")
        if not args.oracle_method.strip():
            raise ValueError("oracle-method must not be empty")
        resolved = [x.resolve() for x in (args.cpu, args.gpu, args.oracle)]
        if len(set(resolved)) != 3:
            raise ValueError("CPU, GPU and oracle must be distinct files")
        loaded = {name: load_f32(getattr(args, name)) for name in ("cpu", "gpu", "oracle")}
        vectors = {name: pair[0] for name, pair in loaded.items()}
        if len({len(v) for v in vectors.values()}) != 1:
            raise ValueError("CPU/GPU/oracle vector dimension mismatch")
        comparisons = {
            "cpu_vs_oracle": metrics(vectors["cpu"], vectors["oracle"], args.relative_floor),
            "gpu_vs_oracle": metrics(vectors["gpu"], vectors["oracle"], args.relative_floor),
            "gpu_vs_cpu": metrics(vectors["gpu"], vectors["cpu"], args.relative_floor),
        }
        checks = {name: (m["max_abs"] <= args.max_abs_tol and
                         m["rms_abs"] <= args.rms_tol and
                         m["cosine_similarity"] >= args.cos_min)
                  for name, m in comparisons.items()}
        receipt = {
            "gate": "DEEP2_KIMI_GPU_MOE_NUMERICAL_PARITY_002",
            "status": "PASS_DIAGNOSTIC" if all(checks.values()) else "FAIL",
            "certified": False,
            "reason": "Requires independently audited oracle, captured input/weight identity and frozen tolerances",
            "layer": args.layer, "expert_id": args.expert_id,
            "token_step": args.token_step, "oracle_method": args.oracle_method,
            "input_sha256": args.input_sha256.lower(),
            "weights_sha256": args.weights_sha256.lower(),
            "vector_sha256": {k: pair[1] for k, pair in loaded.items()},
            "tolerances": {"max_abs": args.max_abs_tol, "rms": args.rms_tol,
                           "cos_min": args.cos_min, "relative_floor": args.relative_floor},
            "comparisons": comparisons, "checks": checks,
            "promote": 0, "tip_climb": "HOLD",
        }
        result = 0 if all(checks.values()) else 2
    except (OSError, ValueError, OverflowError, struct.error) as exc:
        receipt = {"gate": "DEEP2_KIMI_GPU_MOE_NUMERICAL_PARITY_002",
                   "status": "INVALID_INPUT", "certified": False,
                   "error": str(exc), "promote": 0, "tip_climb": "HOLD"}
        result = 3
    payload = json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload, encoding="utf-8")
        except OSError as exc:
            print(f"cannot write receipt: {exc}", file=sys.stderr)
            return 3
    print(payload, end="")
    return result


if __name__ == "__main__":
    sys.exit(main())
