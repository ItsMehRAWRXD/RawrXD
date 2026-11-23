#!/usr/bin/env python3
"""parity_oracle.py -- independent numerical parity oracle for RawrXD.

Compares a candidate per-position logits dump against a reference dump (for
example llama.cpp teacher-forced output) and emits a machine-readable verdict
with first-divergence detection.

A position DIVERGES when any of the configured gates trips:
  * argmax token differs
  * max |cand - ref|            > --max-abs
  * ||cand - ref|| / ||ref||    > --max-rel   (relative L2)
  * cosine(cand, ref)           < --min-cos

Inputs are raw little-endian float32 per-position files. --ref and --cand are
printf-style patterns containing %d for the position, e.g.:

  --ref  ref_logits_pos%d.bin --cand cand_logits_pos%d.f32 --positions 67

Exit codes: 0 = PASS (no divergence within tolerance), 1 = DIVERGENCE,
2 = usage / IO error. --self-test runs a deterministic synthetic check and
exits 0 on success.
"""
import argparse
import json
import math
import struct
import sys


def load_f32(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) % 4 != 0:
        raise ValueError(f"{path}: byte length {len(data)} is not a multiple of 4")
    n = len(data) // 4
    return list(struct.unpack("<%df" % n, data))


def position_metrics(ref, cand):
    n = min(len(ref), len(cand))
    ref = ref[:n]
    cand = cand[:n]
    if n == 0:
        return {
            "n": 0, "cos": 1.0, "maxabs": 0.0, "rmse": 0.0, "rell2": 0.0,
            "argmax_ref": -1, "argmax_cand": -1, "argmax_match": True,
        }
    dot = 0.0
    nr2 = 0.0
    nc2 = 0.0
    sse = 0.0
    maxabs = 0.0
    am_ref = 0
    am_cand = 0
    for i in range(n):
        a = ref[i]
        b = cand[i]
        dot += a * b
        nr2 += a * a
        nc2 += b * b
        d = a - b
        sse += d * d
        ad = abs(d)
        if ad > maxabs:
            maxabs = ad
        if a > ref[am_ref]:
            am_ref = i
        if b > cand[am_cand]:
            am_cand = i
    nr = math.sqrt(nr2)
    nc = math.sqrt(nc2)
    if nr > 0.0 and nc > 0.0:
        cos = dot / (nr * nc)
    elif nr == 0.0 and nc == 0.0:
        cos = 1.0
    else:
        cos = 0.0
    rmse = math.sqrt(sse / n)
    rell2 = (math.sqrt(sse) / nr) if nr > 0.0 else (0.0 if sse == 0.0 else float("inf"))
    return {
        "n": n, "cos": cos, "maxabs": maxabs, "rmse": rmse, "rell2": rell2,
        "argmax_ref": am_ref, "argmax_cand": am_cand,
        "argmax_match": am_ref == am_cand,
    }


def position_diverges(m, max_abs, max_rel, min_cos):
    if not m["argmax_match"]:
        return True
    if m["maxabs"] > max_abs:
        return True
    if m["rell2"] > max_rel:
        return True
    if m["cos"] < min_cos:
        return True
    return False


def run(ref_pat, cand_pat, positions, max_abs, max_rel, min_cos):
    rows = []
    first_div = None
    for p in range(positions):
        ref = load_f32(ref_pat % p)
        cand = load_f32(cand_pat % p)
        m = position_metrics(ref, cand)
        m["pos"] = p
        m["diverges"] = position_diverges(m, max_abs, max_rel, min_cos)
        rows.append(m)
        if m["diverges"] and first_div is None:
            first_div = p
    diverges = sum(1 for r in rows if r["diverges"])
    return {
        "positions": positions,
        "gates": {"max_abs": max_abs, "max_rel": max_rel, "min_cos": min_cos},
        "diverging_positions": diverges,
        "first_divergence": first_div,
        "worst_cos": min((r["cos"] for r in rows), default=1.0),
        "worst_maxabs": max((r["maxabs"] for r in rows), default=0.0),
        "worst_rell2": max((r["rell2"] for r in rows), default=0.0),
        "argmax_matches": sum(1 for r in rows if r["argmax_match"]),
        "verdict": "PASS" if diverges == 0 else "DIVERGENCE",
        "per_position": rows,
    }


def self_test():
    """Deterministic synthetic check: a known divergence must be detected."""
    failures = 0

    def check(cond, what):
        nonlocal failures
        if not cond:
            print("FAIL:", what)
            failures += 1

    # Identical inputs -> no divergence, cosine 1.0.
    ref = [0.1, -0.2, 0.3, 0.4]
    m = position_metrics(ref, list(ref))
    check(m["argmax_match"], "identical argmax")
    check(abs(m["cos"] - 1.0) < 1e-12, "identical cos")
    check(not position_diverges(m, 0.05, 0.05, 0.99), "identical no diverge")

    # Small perturbation within tolerance -> no divergence.
    cand = [x + 0.001 for x in ref]
    m = position_metrics(ref, cand)
    check(not position_diverges(m, 0.05, 0.05, 0.99), "within tolerance")

    # Large perturbation -> divergence.
    cand = [x * 5.0 for x in ref]
    m = position_metrics(ref, cand)
    check(position_diverges(m, 0.05, 0.05, 0.99), "large perturbation diverges")

    # Argmax flip -> divergence even if values are close.
    ref = [0.5, 0.4, 0.3]
    cand = [0.4, 0.5, 0.3]
    m = position_metrics(ref, cand)
    check(not m["argmax_match"], "argmax flip detected")
    check(position_diverges(m, 1.0, 1.0, 0.0), "argmax flip diverges")

    if failures == 0:
        print("SELF_TEST=PASS")
        return 0
    print("SELF_TEST=FAIL failures=%d" % failures)
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="RawrXD independent numerical parity oracle")
    ap.add_argument("--ref", help="printf-style reference path with %d, e.g. ref_pos%d.bin")
    ap.add_argument("--cand", help="printf-style candidate path with %d")
    ap.add_argument("--positions", type=int, help="number of positions to compare")
    ap.add_argument("--out", help="write JSON verdict here")
    ap.add_argument("--max-abs", type=float, default=0.05)
    ap.add_argument("--max-rel", type=float, default=0.05)
    ap.add_argument("--min-cos", type=float, default=0.99)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.ref or not args.cand or args.positions is None:
        ap.error("--ref, --cand and --positions are required (or use --self-test)")

    try:
        result = run(args.ref, args.cand, args.positions,
                     args.max_abs, args.max_rel, args.min_cos)
    except (OSError, ValueError) as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 2

    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())