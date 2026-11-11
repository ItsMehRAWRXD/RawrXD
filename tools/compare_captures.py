#!/usr/bin/env python3
"""RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001 - IR activation capture comparator.

Aligns native Deep2 differential capture records with llama.cpp reference
captures and reports the first numerical divergence in IR execution order.

Native record layout (DifferentialRecorder::SaveAll):
  u32 op_id, u32 layer, u64 position, u32 ndim, i64 dims[ndim], u64 data_size
  (element count), f32 data[]
Reference capture layout:
  u32 magic 0x54434150, u32 version, u64 layer, u32 name_len, char name[],
  u32 ndim, u64 dims[ndim], f32 data[]
"""
import argparse
import json
import math
import os
import re
import struct
import sys

REF_MAGIC = 0x54434150

# (layer, op_id, native record kind) -> reference capture tensor name, in IR order.
MAP = [
    ((0, 0, "Linear_Output"), "inp_embd", 0),
    ((0, 1, "RMSNorm_Output"), "attn_norm", 0),
    ((0, 0, "MLA_kv_latent"), "kv_cmpr", 0),
    ((0, 0, "MLA_k_rope"), "k_pe", 0),
    ((0, 3, "Linear_Output"), "q", 0),
    ((0, 4, "Attention_Output"), "attn_out", 0),
    ((0, 5, "Linear_Output"), "l_out", 0),
    ((0, 7, "RMSNorm_Output"), "ffn_norm", 0),
    ((0, 10, "Linear_Output"), "ffn_out", 0),
]


def parse_native(path):
    with open(path, "rb") as fh:
        d = fh.read()
    (op_id, layer) = struct.unpack_from("<II", d, 0)
    (position,) = struct.unpack_from("<Q", d, 8)
    (ndim,) = struct.unpack_from("<I", d, 16)
    off = 20
    dims = []
    for _ in range(ndim):
        dims.append(struct.unpack_from("<q", d, off)[0])
        off += 8
    (count,) = struct.unpack_from("<Q", d, off)
    off += 8
    if off + count * 4 > len(d):
        raise ValueError("%s: truncated payload" % path)
    payload = d[off:off + count * 4]
    return {"op_id": op_id, "layer": layer, "position": position, "dims": dims,
            "data": struct.unpack("<%df" % count, payload)}


def parse_ref(path):
    with open(path, "rb") as fh:
        d = fh.read()
    (magic,) = struct.unpack_from("<I", d, 0)
    if magic != REF_MAGIC:
        raise ValueError("%s: bad magic 0x%08x" % (path, magic))
    (layer,) = struct.unpack_from("<Q", d, 8)
    (namelen,) = struct.unpack_from("<I", d, 16)
    name = d[20:20 + namelen].decode("ascii", "replace")
    off = 20 + namelen
    (ndim,) = struct.unpack_from("<I", d, off)
    off += 4
    dims = []
    for _ in range(ndim):
        dims.append(struct.unpack_from("<Q", d, off)[0])
        off += 8
    payload = d[off:]
    return {"layer": layer, "name": name, "dims": dims,
            "data": struct.unpack("<%df" % (len(payload) // 4), payload)}


def metrics(a, b):
    n = min(len(a), len(b))
    if n == 0 or n != max(len(a), len(b)):
        return None
    dot = na = nb = se = mx = 0.0
    for i in range(n):
        x, y = a[i], b[i]
        dot += x * y
        na += x * x
        nb += y * y
        se += (x - y) * (x - y)
        mx = max(mx, abs(x - y))
    den = math.sqrt(na * nb)
    amax = max(range(n), key=lambda i: a[i])
    bmax = max(range(n), key=lambda i: b[i])
    return {"count": n, "cosine": (dot / den) if den > 0 else 0.0,
            "rmse": math.sqrt(se / n), "max_abs": mx,
            "native_argmax": amax, "ref_argmax": bmax, "argmax_match": amax == bmax}


NATIVE_NAME = re.compile(r"^rec_\d+_op(\d+)_(.+)_l(\d+)_p(\d+)_(.+)\.bin$")


def index_native(dirpath):
    out = []
    if not os.path.isdir(dirpath):
        return out
    for fn in sorted(os.listdir(dirpath)):
        if not fn.endswith(".bin"):
            continue
        m = NATIVE_NAME.match(fn)
        if not m:
            continue
        try:
            rec = parse_native(os.path.join(dirpath, fn))
        except Exception as exc:  # noqa: BLE001
            print("WARN: skip %s (%s)" % (fn, exc), file=sys.stderr)
            continue
        rec["op_id"] = int(m.group(1))
        rec["layer"] = int(m.group(3))
        rec["position"] = int(m.group(4))
        out.append((fn, m.group(2), rec))
    return out


def index_ref(dirpath):
    out = {}
    if not os.path.isdir(dirpath):
        return out
    for fn in sorted(os.listdir(dirpath)):
        if not fn.endswith(".bin"):
            continue
        try:
            rec = parse_ref(os.path.join(dirpath, fn))
        except Exception:  # noqa: BLE001
            continue
        key = "l%02d" % rec["layer"] if rec["layer"] != 0xFFFFFFFF else "l-1"
        if key not in fn:
            continue
        base = fn.split("_" + key + "_", 1)[1] if ("_" + key + "_") in fn else fn
        base = base[:-4] if base.endswith(".bin") else base
        pos = 0
        if "_p" in base:
            tail = base.rsplit("_p", 1)[1]
            if tail[:2].isdigit():
                pos = int(tail[:2])
        out[(rec["layer"], rec["name"], pos)] = (fn, rec)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--native", required=True)
    ap.add_argument("--ref", required=True)
    ap.add_argument("--layer", type=int, default=0)
    ap.add_argument("--position", type=int, default=0)
    ap.add_argument("--json-out")
    args = ap.parse_args()

    nat = index_native(args.native)
    ref = index_ref(args.ref)

    rows = []
    for (layer, op_id, kind), refname, reflayer in MAP:
        if layer != args.layer:
            continue
        hit = None
        for fn, nk, rec in nat:
            if rec["layer"] != reflayer or rec["op_id"] != op_id:
                continue
            if nk != kind or rec["position"] != args.position:
                continue
            hit = (fn, rec)
            break
        if not hit:
            continue
        r = ref.get((reflayer, refname, args.position))
        if not r:
            rows.append({"kind": kind, "op_id": op_id, "ref": refname, "status": "NO_REF"})
            continue
        m = metrics(hit[1]["data"], r[1]["data"])
        if m is None:
            rows.append({"kind": kind, "op_id": op_id, "ref": refname, "status": "SHAPE_MISMATCH",
                         "native_count": len(hit[1]["data"]), "ref_count": len(r[1]["data"])})
            continue
        m.update({"kind": kind, "op_id": op_id, "ref": refname, "status": "OK",
                  "native_file": hit[0], "ref_file": r[0]})
        rows.append(m)

    print("layer=%d position=%d" % (args.layer, args.position))
    print("%-24s %-5s %-10s %-9s %-11s %-12s %-9s %s" % (
        "tensor", "op", "ref", "n", "cosine", "rmse", "max|d|", "argmax nat/ref"))
    first = None
    for r in rows:
        if r["status"] != "OK":
            print("  %-22s op=%-3s %-10s %s" % (r["kind"], r["op_id"], r["ref"], r["status"]))
            first = first or r["kind"]
            continue
        print("  %-22s op=%-3s %-10s %-9d %-11.6f %-12.6g %-9.4f %d/%d%s" % (
            r["kind"], r["op_id"], r["ref"], r["count"], r["cosine"], r["rmse"],
            r["max_abs"], r["native_argmax"], r["ref_argmax"],
            "" if r["argmax_match"] else "  MISMATCH"))
        if first is None and (r["cosine"] < 0.999999 or not r["argmax_match"]):
            first = r["kind"]

    print("")
    print("FIRST_DIVERGENCE=%s" % (first if first else "NONE"))

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(rows, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
