#!/usr/bin/env python3
"""
first_divergence_compare.py -- M13/M14/M15

Align Deep2 (native ModelGenieExecutor) per-layer tensors against the llama.cpp
reference oracle (llama_dump_intermediate) and report the FIRST divergent
layer/operator.

Both sides are position 0, single token. The reference oracle emits
`<boundary>_L<layer>.bin` as flat float32 in ggml order (ne0 fastest). The native
side emits recorder records `rec_<idx>_op<id>_<op>_l<layer>_p<pos>_<type>.bin`
with a 20-byte header (op_id u32, layer u32, position u64, ndim u32) + int64
shape[] + u64 count + float32 data.

Alignment (native op -> reference boundary), applied per layer:
  RMSNorm_Output  (1st)         -> attn_norm
  RMSNorm_Output  (2nd)         -> ffn_norm
  Linear_Output   shape[3072]   -> q
  Attention_Output shape[2048]  -> attn_preproj
  Output          (mid, 2048)   -> attn_resid   (residual after attention)
  Output          (last, 2048)  -> resid2       (block output = l_out)
  resid_in(L) = resid2(L-1)     (derived on the reference side)

Usage:
  py first_divergence_compare.py \
      --ref  <ref_pos0_dir> \
      --nat  <native_dump_dir> \
      [--threshold 1e-3] [--out <evidence_dir>]
"""
import argparse
import csv
import glob
import json
import os
import struct
import sys

import numpy as np


def read_rec(path):
    b = open(path, "rb").read()
    op_id, layer = struct.unpack_from("<II", b, 0)
    off = 8
    pos, = struct.unpack_from("<Q", b, off); off += 8
    ndim, = struct.unpack_from("<I", b, off); off += 4
    shape = [struct.unpack_from("<q", b, off + 8 * i)[0] for i in range(ndim)]
    off += 8 * ndim
    cnt, = struct.unpack_from("<Q", b, off); off += 8
    data = np.frombuffer(b[off:off + cnt * 4], dtype="<f4").astype(np.float64)
    return {"op_id": op_id, "layer": layer, "pos": pos,
            "shape": shape, "data": data, "file": os.path.basename(path)}


def load_native(nat_dir):
    man = os.path.join(nat_dir, "manifest.json")
    if not os.path.exists(man):
        sys.exit("missing manifest.json in %s" % nat_dir)
    records = json.load(open(man))
    out = []
    for r in records:
        idx = r["index"]
        files = glob.glob(os.path.join(nat_dir, "rec_%06d_*.bin" % idx))
        if not files:
            continue
        rec = read_rec(files[0])
        rec["op_name"] = r["op_name"]
        rec["layer"] = r["layer_idx"]
        rec["position"] = r["position"]
        rec["shape"] = r["shape"]
        rec["index"] = idx
        out.append(rec)
    out.sort(key=lambda x: x["index"])
    return out


def load_ref(ref_dir):
    """Return {(boundary, layer): float64 array}."""
    ref = {}
    for path in glob.glob(os.path.join(ref_dir, "*.bin")):
        name = os.path.basename(path)[:-4]  # strip .bin
        # strip __dupN suffix (keep the first / canonical view)
        base = name.split("__dup")[0]
        if "_" not in base:
            continue
        # boundary may contain underscores? ours don't. split on last _L
        idx = base.rfind("_L")
        if idx < 0:
            continue
        boundary = base[:idx]
        try:
            layer = int(base[idx + 2:])
        except ValueError:
            continue
        arr = np.fromfile(path, dtype="<f4").astype(np.float64)
        key = (boundary, layer)
        # prefer the canonical (non-dup) file; first seen wins
        if key not in ref:
            ref[key] = arr
    return ref


def stats(a, b):
    n = min(a.size, b.size)
    if n == 0:
        return None
    a = a[:n]; b = b[:n]
    d = np.abs(a - b)
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    cos = float(a @ b / (na * nb)) if na > 0 and nb > 0 else float("nan")
    rel = float(np.linalg.norm(a - b) / na) if na > 0 else float("nan")
    return {"n": n, "max_abs": float(d.max()), "mean_abs": float(d.mean()),
            "cos": cos, "rel_l2": rel,
            "first_idx": int(np.argmax(d > 0)) if np.any(d > 0) else -1}


def classify_layer(recs):
    """Map native records of one layer to reference boundaries (execution order)."""
    # recs already ordered by capture index
    mapping = []  # list of (order_in_layer, boundary, rec)
    rms_seen = 0
    outputs_2048 = []
    for r in recs:
        nm = r["op_name"]
        shp = r["shape"]
        if nm == "RMSNorm_Output" and shp == [2048]:
            rms_seen += 1
            b = "attn_norm" if rms_seen == 1 else "ffn_norm"
            mapping.append((r["index"], b, r))
        elif nm == "Linear_Output" and shp == [3072]:
            mapping.append((r["index"], "q", r))
        elif nm == "Attention_Output" and shp == [2048]:
            mapping.append((r["index"], "attn_preproj", r))
        elif nm == "Output" and shp == [2048]:
            outputs_2048.append(r)
        elif nm == "MoE_Output" and shp == [2048]:
            mapping.append((r["index"], "ffn_down_moe", r))
    # outputs_2048: last = resid2 (block out), the one before = attn_resid
    if outputs_2048:
        for r in outputs_2048[:-1]:
            mapping.append((r["index"], "attn_resid", r))
        mapping.append((outputs_2048[-1]["index"], "resid2", outputs_2048[-1]))
    mapping.sort(key=lambda t: t[0])
    return mapping


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", required=True)
    ap.add_argument("--nat", required=True)
    ap.add_argument("--threshold", type=float, default=1e-3)
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-layer", type=int, default=26)
    args = ap.parse_args()

    ref = load_ref(args.ref)
    nat = load_native(args.nat)

    # group native by layer (exclude global 4294967295)
    layers = {}
    for r in nat:
        if r["layer"] == 4294967295:
            continue
        layers.setdefault(r["layer"], []).append(r)

    rows = []
    # execution order of boundaries within a layer
    ORDER = ["resid_in", "attn_norm", "q", "k", "v", "attn_preproj",
             "attn_resid", "ffn_norm", "ffn_gate", "ffn_up", "ffn_swiglu",
             "ffn_down", "ffn_down_moe", "resid2"]

    for L in range(0, args.max_layer + 1):
        if L not in layers:
            continue
        mapping = classify_layer(layers[L])
        # resid_in for layer L is the reference residual entering L (= resid2 L-1)
        ref_resid_in = ref.get(("resid2", L - 1))
        for order, boundary, rec in mapping:
            if boundary == "ffn_down_moe":
                continue  # MoE full output vs reference shared-expert down: not comparable
            if boundary == "resid_in":
                r = ref_resid_in
            else:
                r = ref.get((boundary, L))
            if r is None:
                continue
            s = stats(rec["data"], r)
            if s is None:
                continue
            s.update({"layer": L, "boundary": boundary,
                      "ref_size": int(r.size), "nat_size": int(rec["data"].size)})
            rows.append(s)

    # ---- report -----------------------------------------------------------
    # Determine first divergence: earliest layer, then earliest boundary in ORDER.
    def order_key(row):
        try:
            return ORDER.index(row["boundary"])
        except ValueError:
            return len(ORDER)

    div = [r for r in rows if r["max_abs"] > args.threshold]
    div.sort(key=lambda r: (r["layer"], order_key(r)))
    first = div[0] if div else None

    # ---- print per-layer table for key boundaries -------------------------
    print("=" * 96)
    print("Per-layer max|abs diff| (Deep2 native vs llama.cpp reference), pos0 token=1")
    print("=" * 96)
    key_b = ["attn_norm", "q", "attn_preproj", "attn_resid", "ffn_norm", "resid2"]
    hdr = "L   " + "".join("%-14s" % b for b in key_b)
    print(hdr)
    for L in range(0, args.max_layer + 1):
        cells = []
        for b in key_b:
            m = [r for r in rows if r["layer"] == L and r["boundary"] == b]
            if m:
                cells.append("%-14.4e" % m[0]["max_abs"])
            else:
                cells.append("%-14s" % "-")
        print("%-3d " % L + "".join(cells))

    print("\nCosine similarity per layer (key boundaries):")
    print("L   " + "".join("%-14s" % b for b in key_b))
    for L in range(0, args.max_layer + 1):
        cells = []
        for b in key_b:
            m = [r for r in rows if r["layer"] == L and r["boundary"] == b]
            cells.append("%-14.8f" % m[0]["cos"] if m else "%-14s" % "-")
        print("%-3d " % L + "".join(cells))

    # ---- first divergence -------------------------------------------------
    print("\n" + "=" * 96)
    if first:
        print("FIRST DIVERGENCE (max_abs > %.1e):" % args.threshold)
        print("  layer    : %d" % first["layer"])
        print("  operator : %s" % first["boundary"])
        print("  max_abs  : %.6e" % first["max_abs"])
        print("  mean_abs : %.6e" % first["mean_abs"])
        print("  cos      : %.8f" % first["cos"])
        print("  rel_l2   : %.6e" % first["rel_l2"])
        print("  sizes    : native=%d ref=%d" % (first["nat_size"], first["ref_size"]))
    else:
        print("No tensor exceeded threshold %.1e." % args.threshold)

    # ---- write artifacts --------------------------------------------------
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "per_tensor_diff.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["layer", "boundary", "n", "max_abs", "mean_abs",
                        "cos", "rel_l2", "nat_size", "ref_size"])
            for r in sorted(rows, key=lambda r: (r["layer"], order_key(r))):
                w.writerow([r["layer"], r["boundary"], r["n"],
                            "%.6e" % r["max_abs"], "%.6e" % r["mean_abs"],
                            "%.8f" % r["cos"], "%.6e" % r["rel_l2"],
                            r["nat_size"], r["ref_size"]])
        summary = {
            "ref_dir": os.path.abspath(args.ref),
            "native_dir": os.path.abspath(args.nat),
            "threshold": args.threshold,
            "first_divergence": first,
            "num_tensors_compared": len(rows),
        }
        json.dump(summary, open(os.path.join(args.out, "first_divergence.json"), "w"), indent=2)
        print("\nWrote per_tensor_diff.csv and first_divergence.json to %s" % args.out)


if __name__ == "__main__":
    main()