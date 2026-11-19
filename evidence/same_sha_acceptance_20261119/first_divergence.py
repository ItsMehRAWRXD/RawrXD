#!/usr/bin/env python3
"""FIRST_DIVERGENCE_001 - locate the first operator where Deep2 diverges.

Inputs
  --trace-dir  directory holding RAWRXD_OP_TRACE_META_001 output
               (cpu_pos0_ops_metadata.json / gpu_pos0_ops_metadata.json
                plus <backend>_pos0_op<N>.f32 payloads)
  --ref        llama_dump_intermediate output dir (pos0/)
  --position   0-based position (default 0)

Method
  Walk Deep2 ops in program order. For every op that has a llama.cpp
  boundary with identical element count, compare element-wise
  (cosine, max |delta|, rmse). The first op whose cosine drops below
  --cos-tol is reported as the first divergent operation; ops before it
  are the last matching prefix.
"""
import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np

# Deep2 op name -> llama.cpp boundary prefix.  Evaluated per block.
NAME_MAP = {
    "attn_norm": "attn_norm",
    "q": "q",
    "k": "k",
    "v": "v",
    "attn_out": "attn_preproj",
    "attn_proj": "attn_proj",
    "resid1": "attn_resid",
    "ffn_norm": "ffn_norm",
    "gate": "ffn_gate",
    "up": "ffn_up",
    "swiglu": "ffn_swiglu",
    "ffn_out": "ffn_down",
    "resid2": "resid2",
    "resid_in": "resid_in",
}

SKIP_OPS = {"token_embd.weight"}


def load_f32(path: Path) -> np.ndarray:
    return np.fromfile(path, dtype="<f4").astype(np.float64)


def ref_candidates(ref_dir: Path, boundary: str, block: int) -> list[Path]:
    """Canonical boundary plus head-split / roped duplicates.

    llama.cpp emits several nodes that map to the same Deep2 boundary
    (Qcur vs Qcur_roped, pre/post head-split views).  The trace captures the
    post-RoPE form, so every variant must be offered and the closest one chosen
    rather than assuming the canonical spelling.
    """
    out = []
    base = ref_dir / f"{boundary}_L{block}.bin"
    if base.exists():
        out.append(base)
    out.extend(sorted(ref_dir.glob(f"{boundary}_L{block}__dup*.bin")))
    return out


def metrics(a: np.ndarray, b: np.ndarray) -> dict:
    n = min(a.size, b.size)
    a = a[:n]
    b = b[:n]
    d = a - b
    na = math.sqrt(float(a @ a))
    nb = math.sqrt(float(b @ b))
    cos = float(a @ b) / (na * nb) if na > 0 and nb > 0 else float("nan")
    return {
        "elements": n,
        "cosine": cos,
        "max_abs": float(np.max(np.abs(d))),
        "rmse": float(math.sqrt(float(d @ d) / n)),
        "ref_rms": float(math.sqrt(float(b @ b) / n)),
        "delta_rms": float(math.sqrt(float(d @ d) / n)),
    }


def run(backend: str, trace_dir: Path, ref_dir: Path, position: int, cos_tol: float):
    meta_file = trace_dir / f"{backend}_pos{position}_ops_metadata.json"
    if not meta_file.exists():
        alt = trace_dir / f"{backend}_pos{position}_op_metadata.json"
        if alt.exists():
            meta_file = alt
        else:
            return {"backend": backend, "error": f"missing {meta_file.name}"}
    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    rows = []
    for op in meta.get("ops", []):
        name = op.get("name", "")
        block = int(op.get("block", -1))
        idx = int(op.get("op_index", -1))
        if name in SKIP_OPS:
            rows.append({"op_index": idx, "block": block, "name": name,
                         "status": "NO_REFERENCE_BOUNDARY"})
            continue
        boundary = NAME_MAP.get(name)
        if boundary is None:
            rows.append({"op_index": idx, "block": block, "name": name,
                         "status": "UNMAPPED"})
            continue
        if block == 0 and name == "resid_in":
            rows.append({"op_index": idx, "block": block, "name": name,
                         "status": "NO_REFERENCE_BOUNDARY"})
            continue
        rp = ref_candidates(ref_dir, boundary, block)
        if not rp:
            rows.append({"op_index": idx, "block": block, "name": name,
                         "boundary": boundary, "status": "REFERENCE_MISSING"})
            continue
        payload = trace_dir / f"{backend}_pos{position}_op{idx}.f32"
        if not payload.exists():
            rows.append({"op_index": idx, "block": block, "name": name,
                         "boundary": boundary, "status": "PAYLOAD_MISSING"})
            continue
        a = load_f32(payload)
        best = None
        size_mismatch = None
        for cand in rp:
            b = load_f32(cand)
            if a.size != b.size:
                size_mismatch = (int(a.size), int(b.size))
                continue
            m = metrics(a, b)
            if best is None or m["cosine"] > best[1]["cosine"]:
                best = (cand, m)
        if best is None:
            rows.append({"op_index": idx, "block": block, "name": name,
                         "boundary": boundary,
                         "status": "SIZE_MISMATCH",
                         "deep2_elements": size_mismatch[0] if size_mismatch else None,
                         "reference_elements": size_mismatch[1] if size_mismatch else None})
            continue
        cand, m = best
        m.update({"op_index": idx, "block": block, "name": name,
                  "boundary": cand.name,
                  "boundary_variants": [c.name for c in rp],
                  "status": "COMPARED"})
        rows.append(m)

    first = None
    for r in rows:
        if r.get("status") == "COMPARED" and r["cosine"] < cos_tol:
            first = r
            break
    compared = [r for r in rows if r.get("status") == "COMPARED"]
    return {
        "backend": backend,
        "meta_schema": meta.get("schema"),
        "position": position,
        "op_count": len(rows),
        "compared": len(compared),
        "cos_tol": cos_tol,
        "first_divergent_op_index": first["op_index"] if first else None,
        "first_divergent_op_name": first["name"] if first else None,
        "first_divergent_block": first["block"] if first else None,
        "first_divergent_cosine": first["cosine"] if first else None,
        "last_matching_op_index": (first["op_index"] - 1) if first else None,
        "rows": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace-dir", required=True)
    ap.add_argument("--ref", required=True)
    ap.add_argument("--position", type=int, default=0)
    ap.add_argument("--cos-tol", type=float, default=0.9999)
    ap.add_argument("--out")
    args = ap.parse_args()

    trace_dir = Path(args.trace_dir)
    ref_dir = Path(args.ref) / f"pos{args.position}"
    report = {
        "schema": "FIRST_DIVERGENCE_001/v1",
        "trace_dir": str(trace_dir),
        "reference_dir": str(ref_dir),
        "backends": {},
    }
    for backend in ("cpu", "gpu"):
        report["backends"][backend] = run(backend, trace_dir, ref_dir,
                                          args.position, args.cos_tol)

    for backend, r in report["backends"].items():
        if "error" in r:
            print(f"{backend}: {r['error']}")
            continue
        print(f"[{backend}] compared={r['compared']} "
              f"first_divergent_op={r['first_divergent_op_index']} "
              f"name={r['first_divergent_op_name']} block={r['first_divergent_block']} "
              f"cos={r['first_divergent_cosine']}")
        for row in r["rows"]:
            if row.get("status") != "COMPARED":
                continue
            if r["first_divergent_op_index"] is not None and \
               row["op_index"] > r["first_divergent_op_index"] + 3:
                break
            print(f"  op{row['op_index']:>3} blk={row['block']:>2} {row['name']:<12} "
                  f"cos={row['cosine']:.8f} max_abs={row['max_abs']:.6g} "
                  f"rel={row['delta_rms'] / row['ref_rms'] if row['ref_rms'] else float('nan'):.3e}")

    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())