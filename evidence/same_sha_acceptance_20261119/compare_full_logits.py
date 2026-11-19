#!/usr/bin/env python3
"""Full-vocabulary logit comparison: Deep2 (GPU) vs llama.cpp (CPU reference).

Inputs
  --deep2   file written by ltt_tensor_invoke --logits-out:
            repeated records of [uint64 count][float32 * count]
  --ref     directory written by llama_dump_intermediate:
            pos<N>/logits.bin = raw float32 * n_vocab

Output
  JSON report on stdout (+ optional --out path).
"""
import argparse
import json
import math
import struct
import sys
from pathlib import Path

import numpy as np


def load_deep2(path: Path):
    raw = path.read_bytes()
    off = 0
    rows = []
    while off < len(raw):
        if off + 8 > len(raw):
            raise ValueError(f"truncated count at byte {off}")
        (count,) = struct.unpack_from("<Q", raw, off)
        off += 8
        need = count * 4
        if off + need > len(raw):
            raise ValueError(f"truncated payload at byte {off}: want {need}")
        rows.append(np.frombuffer(raw, dtype="<f4", count=count, offset=off).astype(np.float64))
        off += need
    return rows


def load_ref(ref_dir: Path):
    rows = []
    for d in sorted(ref_dir.glob("pos*"), key=lambda p: int(p.name[3:])):
        f = d / "logits.bin"
        if not f.exists():
            continue
        rows.append(np.fromfile(f, dtype="<f4").astype(np.float64))
    return rows


def compare(a, b):
    n = min(a.size, b.size)
    a = a[:n]
    b = b[:n]
    diff = a - b
    denom = math.sqrt(float(a @ a)) * math.sqrt(float(b @ b))
    cos = float(a @ b) / denom if denom > 0 else float("nan")
    max_abs = float(np.max(np.abs(diff)))
    rmse = float(math.sqrt(float(diff @ diff) / n))
    amax_a = int(np.argmax(a))
    amax_b = int(np.argmax(b))
    top_a = set(np.argsort(a)[-10:][::-1].tolist())
    top_b = set(np.argsort(b)[-10:][::-1].tolist())
    return {
        "elements": n,
        "cosine": cos,
        "max_abs": max_abs,
        "rmse": rmse,
        "argmax_deep2": amax_a,
        "argmax_reference": amax_b,
        "argmax_match": amax_a == amax_b,
        "top10_overlap": len(top_a & top_b),
        "coeff_abs_gt_1e-3": int(np.count_nonzero(np.abs(diff) > 1e-3)),
        "nonfinite_deep2": int(np.count_nonzero(~np.isfinite(a))),
        "nonfinite_reference": int(np.count_nonzero(~np.isfinite(b))),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deep2", required=True)
    ap.add_argument("--ref", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()

    d2 = load_deep2(Path(args.deep2))
    ref = load_ref(Path(args.ref))
    if not d2:
        print("no deep2 rows", file=sys.stderr)
        return 2
    if not ref:
        print("no reference rows", file=sys.stderr)
        return 2
    if len(d2) != len(ref):
        print(f"row count mismatch deep2={len(d2)} ref={len(ref)}", file=sys.stderr)

    positions = []
    for i, (a, b) in enumerate(zip(d2, ref)):
        positions.append(compare(a, b))

    cosines = [p["cosine"] for p in positions]
    report = {
        "schema": "FULL_LOGIT_PARITY_001/v1",
        "positions_compared": min(len(d2), len(ref)),
        "deep2_rows": len(d2),
        "reference_rows": len(ref),
        "min_cosine": min(cosines),
        "mean_cosine": sum(cosines) / len(cosines),
        "max_abs_worst": max(p["max_abs"] for p in positions),
        "argmax_exact_positions": sum(1 for p in positions if p["argmax_match"]),
        "all_finite": all(
            p["nonfinite_deep2"] == 0 and p["nonfinite_reference"] == 0 for p in positions
        ),
        "positions": positions,
    }
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())