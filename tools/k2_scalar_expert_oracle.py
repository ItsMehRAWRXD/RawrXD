#!/usr/bin/env python3
"""Independent Kimi K2 expert path: Q4_K gate/up, SwiGLU, Q6_K down.

No host QuantKernelRegistry or GPU implementation is used. This is a scalar
numerical reference, not evidence that a real model or GPU was exercised.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
from k2_q4k_scalar_oracle import gemv as q4_gemv
from k2_q6k_scalar_oracle import gemv as q6_gemv


def swiglu(gate, up):
    if len(gate) != len(up):
        raise ValueError("gate/up dimensions differ")
    values = []
    for g, u in zip(gate, up):
        if not math.isfinite(g) or not math.isfinite(u):
            raise ValueError("nonfinite gate/up activation")
        sigmoid = 1 / (1 + math.exp(-g)) if g >= 0 else math.exp(g) / (1 + math.exp(g))
        value = g * sigmoid * u
        if not math.isfinite(value):
            raise ValueError("nonfinite SwiGLU activation")
        values.append(value)
    return values


def expert(gate_weights, up_weights, down_weights, hidden, h, intermediate):
    if h <= 0 or intermediate <= 0 or h % 256 or intermediate % 256:
        raise ValueError("invalid expert shape (QK_K=256)")
    gate = q4_gemv(gate_weights, hidden, intermediate, h)
    up = q4_gemv(up_weights, hidden, intermediate, h)
    intermediate_activation = swiglu(gate, up)
    down = q6_gemv(down_weights, intermediate_activation, h, intermediate)
    return {"gate": gate, "up": up, "post_swiglu": intermediate_activation,
            "down": down}


def read_vector(path):
    raw = path.read_bytes()
    values = [float(line.split("#", 1)[0].strip()) for line in
              raw.decode("utf-8").splitlines() if line.split("#", 1)[0].strip()]
    if not values or not all(math.isfinite(v) for v in values):
        raise ValueError("empty or nonfinite hidden input")
    return values, raw


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gate", required=True, type=Path)
    p.add_argument("--up", required=True, type=Path)
    p.add_argument("--down", required=True, type=Path)
    p.add_argument("--hidden", required=True, type=Path)
    p.add_argument("--hidden-dim", type=int, required=True)
    p.add_argument("--intermediate-dim", type=int, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if not args.output_dir.is_dir():
            raise ValueError("existing private output directory required")
        blobs = {name: path.read_bytes() for name, path in
                 (("gate", args.gate), ("up", args.up), ("down", args.down))}
        hidden, hidden_raw = read_vector(args.hidden)
        if len(hidden) != args.hidden_dim:
            raise ValueError("hidden vector shape mismatch")
        results = expert(blobs["gate"], blobs["up"], blobs["down"],
                         hidden, args.hidden_dim, args.intermediate_dim)
        output_sha = {}
        for name, values in results.items():
            target = args.output_dir / ("scalar_" + name + ".txt")
            if target.exists():
                raise ValueError("refusing to overwrite oracle output: " + str(target))
            raw = "".join(f"{v:.17g}\n" for v in values).encode("utf-8")
            target.write_bytes(raw)
            output_sha[name] = hashlib.sha256(raw).hexdigest()
        receipt = {
            "schema": "DEEP2_KIMI_SCALAR_EXPERT_001/v1",
            "status": "PASS_DIAGNOSTIC", "certified": False,
            "hidden_dim": args.hidden_dim,
            "intermediate_dim": args.intermediate_dim,
            "quant_types": {"gate": 12, "up": 12, "down": 14},
            "input_sha256": {
                **{k: hashlib.sha256(v).hexdigest() for k, v in blobs.items()},
                "hidden": hashlib.sha256(hidden_raw).hexdigest()},
            "output_sha256": output_sha,
            "note": "Full scalar expert path; no GPU activation identity, execution or production parity proven",
        }
        code = 0
    except (OSError, ValueError, OverflowError, UnicodeError) as exc:
        receipt = {"schema": "DEEP2_KIMI_SCALAR_EXPERT_001/v1",
                   "status": "ERROR", "certified": False, "error": str(exc)}
        code = 3
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
    print(receipt["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
