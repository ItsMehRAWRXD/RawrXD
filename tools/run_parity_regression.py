"""Deterministic offline Deep2/reference parity regression.

The harness refuses mismatched row counts and reports full-vocabulary metrics.
It does not convert bounded agreement into strict parity.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def compare(a: np.ndarray, b: np.ndarray) -> dict:
    if a.size != b.size:
        raise ValueError(f"row size mismatch deep2={a.size} reference={b.size}")
    d = a - b
    return {
        "elements": int(a.size),
        "cosine": float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b))),
        "rms": float(np.sqrt(np.mean(d * d))),
        "max_abs": float(np.max(np.abs(d))),
        "argmax_match": bool(a.argmax() == b.argmax()),
        "top10_overlap": int(len(set(np.argsort(a)[-10:]) & set(np.argsort(b)[-10:]))),
        "finite": bool(np.isfinite(a).all() and np.isfinite(b).all()),
    }


def run(args: argparse.Namespace) -> int:
    root = Path(args.root)
    rows = []
    for pos in range(args.positions):
        d2 = root / "certify_qwen_1p5b" / f"gpu_logits_pos{pos}.bin"
        ref = root / "ref_logits" / f"ref_logits_pos{pos}.bin"
        if not d2.exists() or not ref.exists():
            print(f"MISSING position={pos} deep2={d2.exists()} reference={ref.exists()}")
            return 2
        rows.append({"position": pos, **compare(
            np.fromfile(d2, dtype="<f4").astype(np.float64),
            np.fromfile(ref, dtype="<f4").astype(np.float64),
        )})
    report = {
        "positions": rows,
        "positions_compared": len(rows),
        "all_finite": all(r["finite"] for r in rows),
        "top1_exact": sum(r["argmax_match"] for r in rows),
        "min_cosine": min(r["cosine"] for r in rows),
        "max_abs_worst": max(r["max_abs"] for r in rows),
    }
    print(json.dumps(report, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    strict = (
        report["all_finite"]
        and report["top1_exact"] == args.positions
        and report["min_cosine"] >= args.cosine
        and report["max_abs_worst"] <= args.max_abs
    )
    print(f"STRICT_PARITY={'PASS' if strict else 'FAIL'}")
    return 0 if strict else 5


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--positions", type=int, default=5)
    ap.add_argument("--cosine", type=float, default=0.999999)
    ap.add_argument("--max-abs", type=float, default=1.0e-4)
    ap.add_argument("--out")
    return run(ap.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
