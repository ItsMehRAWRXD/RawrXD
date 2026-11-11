#!/usr/bin/env python3
"""Independent Qwen3.6 GDN CPU parity checker.

The checker intentionally does not import Deep2 or call its C++ reference.
It consumes the diagnostic boundary witness emitted by DEEP2_GDN_DUMP_DIR and
recomputes the gated-delta recurrence using Python scalar arithmetic.
"""

from __future__ import annotations

import argparse
import array
import json
import math
import pathlib
import re
import struct
from typing import Iterable


HKEY = 16
HVALUE = 32
HEAD_DIM = 128
STATE_SIZE = HVALUE * HEAD_DIM * HEAD_DIM
EPS_NORM = 1.0e-6
EPS_RMS = 1.0e-5


def read_f32(path: pathlib.Path) -> list[float]:
    raw = path.read_bytes()
    if len(raw) % 4:
        raise ValueError(f"{path.name}: byte count is not a float32 multiple")
    return list(array.array("f", raw))


def softplus(value: float) -> float:
    if value > 20.0:
        return value
    if value < -20.0:
        return math.exp(value)
    return math.log1p(math.exp(value))


def sigmoid(value: float) -> float:
    if value >= 0.0:
        e = math.exp(-value)
        return 1.0 / (1.0 + e)
    e = math.exp(value)
    return e / (1.0 + e)


def finite(values: Iterable[float]) -> bool:
    return all(math.isfinite(v) for v in values)


def reference_step(mixed: list[float], beta_logits: list[float], alpha_logits: list[float],
                   a_log: list[float], dt_bias: list[float], norm: list[float],
                   gate: list[float], state: list[float]) -> tuple[list[float], list[float]]:
    expected_mixed = (2 * HKEY + HVALUE) * HEAD_DIM
    if len(mixed) != expected_mixed:
        raise ValueError(f"mixed length {len(mixed)} != {expected_mixed}")
    if any(len(v) != HVALUE for v in (beta_logits, alpha_logits, a_log, dt_bias)):
        raise ValueError("per-head operand length is not 32")
    if len(norm) != HEAD_DIM or len(gate) != HVALUE * HEAD_DIM:
        raise ValueError("norm/gate geometry mismatch")
    if len(state) != STATE_SIZE:
        raise ValueError(f"state length {len(state)} != {STATE_SIZE}")

    out = [0.0] * (HVALUE * HEAD_DIM)
    scale = 1.0 / math.sqrt(float(HEAD_DIM))
    heads_per_key = HVALUE // HKEY
    for hv in range(HVALUE):
        hk = hv // heads_per_key
        qbase = hk * HEAD_DIM
        kbase = (HKEY + hk) * HEAD_DIM
        vbase = (2 * HKEY + hv) * HEAD_DIM
        sbase = hv * HEAD_DIM * HEAD_DIM

        qsq = sum(mixed[qbase + d] * mixed[qbase + d] for d in range(HEAD_DIM))
        ksq = sum(mixed[kbase + d] * mixed[kbase + d] for d in range(HEAD_DIM))
        qinv = 1.0 / math.sqrt(qsq + EPS_NORM)
        kinv = 1.0 / math.sqrt(ksq + EPS_NORM)
        decay = -math.exp(a_log[hv]) * softplus(alpha_logits[hv] + dt_bias[hv])
        decay_factor = math.exp(decay)
        beta = sigmoid(beta_logits[hv])
        if not (math.isfinite(decay_factor) and math.isfinite(beta)):
            raise ValueError(f"nonfinite gate at value head {hv}")

        nxt = [0.0] * HEAD_DIM
        for vv in range(HEAD_DIM):
            dot = 0.0
            row = sbase + vv * HEAD_DIM
            for kk in range(HEAD_DIM):
                key = mixed[kbase + kk] * kinv
                state[row + kk] *= decay_factor
                dot += state[row + kk] * key
            value = (mixed[vbase + vv] - dot) * beta
            acc = 0.0
            for kk in range(HEAD_DIM):
                key = mixed[kbase + kk] * kinv
                state[row + kk] += value * key
                query = mixed[qbase + kk] * qinv
                acc += state[row + kk] * query * scale
            nxt[vv] = acc

        rms = 1.0 / math.sqrt(sum(v * v for v in nxt) / HEAD_DIM + EPS_RMS)
        for vv, value in enumerate(nxt):
            gate_value = gate[hv * HEAD_DIM + vv] * sigmoid(gate[hv * HEAD_DIM + vv])
            out[hv * HEAD_DIM + vv] = value * rms * norm[vv] * gate_value
    if not finite(out) or not finite(state):
        raise ValueError("reference produced nonfinite values")
    return out, state


def metrics(actual: list[float], expected: list[float]) -> dict[str, float | int]:
    if len(actual) != len(expected):
        raise ValueError(f"length mismatch {len(actual)} != {len(expected)}")
    errors = [abs(a - b) for a, b in zip(actual, expected)]
    max_abs = max(errors, default=0.0)
    mean_abs = sum(errors) / len(errors) if errors else 0.0
    rms = math.sqrt(sum(e * e for e in errors) / len(errors)) if errors else 0.0
    worst = max(range(len(errors)), key=errors.__getitem__) if errors else 0
    return {"count": len(errors), "max_abs": max_abs, "mean_abs": mean_abs,
            "rms": rms, "worst_index": worst}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dump_dir", type=pathlib.Path)
    ap.add_argument("--block", type=int, default=0)
    ap.add_argument("--max-steps", type=int, default=0)
    ap.add_argument("--max-abs", type=float, default=2.0e-5)
    ap.add_argument("--receipt", type=pathlib.Path)
    args = ap.parse_args()

    pattern = re.compile(rf"gdn_b{args.block}_t(\d+)_mixed\.f32$")
    steps = sorted((int(m.group(1)), p) for p in args.dump_dir.iterdir()
                   if (m := pattern.match(p.name)))
    if args.max_steps:
        steps = steps[:args.max_steps]
    if not steps:
        raise SystemExit("no GDN mixed-input witnesses found")

    results = []
    for step, mixed_path in steps:
        prefix = mixed_path.name[:-len("mixed.f32")]
        def load(tag: str) -> list[float]:
            return read_f32(args.dump_dir / f"{prefix}{tag}.f32")

        mixed = load("mixed")
        beta = load("beta_logits")
        alpha = load("alpha_logits")
        a_log = load("a_log")
        dt_bias = load("dt_bias")
        norm = load("norm")
        gate = load("gate")
        before = load("state_before")
        recorded_state = load("state_after")
        recorded_output = load("output")
        expected_output, expected_state = reference_step(
            mixed, beta, alpha, a_log, dt_bias, norm, gate, before[:])
        output_m = metrics(recorded_output, expected_output)
        state_m = metrics(recorded_state, expected_state)
        passed = (output_m["max_abs"] <= args.max_abs and
                  state_m["max_abs"] <= args.max_abs)
        results.append({"step": step, "pass": passed,
                        "output": output_m, "state": state_m})

    receipt = {
        "schema": "rawrxd.qwen36.gdn.cpu.parity.v1",
        "block": args.block,
        "steps": results,
        "max_abs_tolerance": args.max_abs,
        "pass": all(r["pass"] for r in results),
        "independent_reference": "python-scalar-gdn-recurrence",
    }
    text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.receipt:
        args.receipt.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if receipt["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
