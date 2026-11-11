#!/usr/bin/env python3
"""Position-0 divergence tracer - RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001

Walks the layer-0 IR chain in execution order and prints cosine / RMSE /
norm-ratio for the first tensor whose error is not pure quantization noise,
so the first genuine numerical divergence is isolated.
"""
import glob
import math
import os
import struct
import sys

REF = r"evidence/NUGVERSE_ESTIMATOR_001/ref_capture_v9"
NAT = sys.argv[1] if len(sys.argv) > 1 else "tmp_build_mg/native_p0"
POS = int(sys.argv[2]) if len(sys.argv) > 2 else 0


def rd_nat(p):
    d = open(p, "rb").read()
    op, layer = struct.unpack_from("<II", d, 0)
    pos = struct.unpack_from("<Q", d, 8)[0]
    (nd,) = struct.unpack_from("<I", d, 16)
    off = 20
    dims = [struct.unpack_from("<q", d, off + 8 * j)[0] for j in range(nd)]
    off += 8 * nd
    (cnt,) = struct.unpack_from("<Q", d, off)
    off += 8
    return {"op": op, "layer": layer, "pos": pos, "dims": dims,
            "v": struct.unpack("<%df" % cnt, d[off:off + cnt * 4])}


def rd_ref(p):
    d = open(p, "rb").read()
    (magic,) = struct.unpack_from("<I", d, 0)
    assert magic == 0x54434150, hex(magic)
    (layer,) = struct.unpack_from("<Q", d, 8)
    (nlen,) = struct.unpack_from("<I", d, 16)
    name = d[20:20 + nlen].decode()
    off = 20 + nlen
    (nd,) = struct.unpack_from("<I", d, off)
    off += 4
    dims = [struct.unpack_from("<Q", d, off + 8 * j)[0] for j in range(nd)]
    off += 8 * nd
    return {"layer": layer, "name": name, "dims": dims,
            "v": struct.unpack("<%df" % ((len(d) - off) // 4), d[off:])}


def met(a, b):
    n = min(len(a), len(b))
    if n == 0 or n != max(len(a), len(b)):
        return None
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    cos = dot / (na * nb) if na > 0 and nb > 0 else 0.0
    rm = math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)) / n)
    mx = max(abs(x - y) for x, y in zip(a, b))
    return n, cos, rm, mx, (na / nb if nb > 0 else 0.0)


# (native filename marker, reference file) in IR execution order for layer 0.
CHAIN = [
    ("op0_Linear_Output_l4294967295", "ref_l-1_p%02d_inp_embd.bin"),
    ("op1_RMSNorm_Output",            "ref_l00_p%02d_attn_norm.bin"),
    ("MLA_kv_latent",                 "ref_l00_p%02d_kv_cmpr.bin"),
    ("MLA_k_rope",                    "ref_l00_p%02d_k_pe.bin"),
    ("op3_Linear_Output",             "ref_l00_p%02d_q.bin"),
    ("op5_Linear_Output",             "ref_l00_p%02d_attn_out.bin"),
    ("op7_RMSNorm_Output",            "ref_l00_p%02d_ffn_norm.bin"),
    ("op10_Linear_Output",            "ref_l00_p%02d_ffn_out.bin"),
    ("op11_Output",                   "ref_l00_p%02d_l_out.bin"),
]


def main():
    nat_files = {}
    for p in sorted(glob.glob(os.path.join(NAT, "*.bin"))):
        r = rd_nat(p)
        if r["pos"] == POS:
            nat_files[r["op"]] = (os.path.basename(p), r)

    print("position %d   native=%s   ref=%s" % (POS, NAT, REF))
    print("%-30s %-20s %7s %11s %11s %11s %10s" %
          ("native", "ref", "n", "cosine", "rmse", "max|d|", "norm_ratio"))
    first_bad = None
    for marker, refname in CHAIN:
        op = None
        for cand, _ in nat_files.items():
            pass
        hit = None
        for cand, (fname, rec) in nat_files.items():
            if marker.startswith("op"):
                pass
        # resolve by explicit op id embedded in the marker
        opid = None
        if marker.startswith("op"):
            opid = int(marker[2:].split("_")[0])
        for op, (fname, rec) in nat_files.items():
            if opid is not None and op != opid:
                continue
            if marker.startswith("MLA") and marker not in fname:
                continue
            if opid is not None and marker not in fname:
                continue
            hit = (fname, rec)
            break
        if not hit:
            print("%-30s %-20s %s" % (marker, refname % POS, "NO_NATIVE"))
            continue
        refpath = os.path.join(REF, refname % POS)
        if not os.path.exists(refpath):
            print("%-30s %-20s %s" % (marker, refname % POS, "NO_REF"))
            continue
        r = rd_ref(refpath)
        m = met(hit[1]["v"], r["v"])
        if m is None:
            print("%-30s %-20s SHAPE %d vs %d" % (marker, refname % POS,
                                                 len(hit[1]["v"]), len(r["v"])))
            continue
        n, cos, rm, mx, nr = m
        flag = ""
        if cos < 0.999999 or rm > 1e-3:
            flag = "  <== DIVERGENT"
            if first_bad is None:
                first_bad = marker
        print("%-30s %-20s %7d %11.7f %11.6g %11.6g %10.7f%s" %
              (marker, refname % POS, n, cos, rm, mx, nr, flag))
    print("\nFIRST_DIVERGENT = %s" % (first_bad or "NONE"))


if __name__ == "__main__":
    main()
