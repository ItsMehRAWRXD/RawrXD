#!/usr/bin/env python3
"""q4k_oracle_gate.py — LOGITS_PARITY_001, independent numerical oracle.

Compares Deep2's traced activations against a reimplementation that never links
Deep2 and never shares its kernels. The reference reads Q4_K weights directly
out of the GGUF bytes and dequantizes them with numpy, so a bug in Deep2's
GEMV cannot hide behind a matching bug here.

Scope and honesty:
  * This gate adjudicates ONE 256-value Q4_K block axis at a time. It proves
    the dequant + dot product agree with an independent implementation for the
    surfaces it covers. It does not adjudicate the full 64-layer forward pass.
  * A PASS here means "no divergence found in the covered surfaces". It is not
    a claim that Deep2 is numerically correct everywhere.
  * Any surface that cannot be adjudicated is reported as NOT_ADJUDICATED, never
    as PASS.

Usage:
  py -3 q4k_oracle_gate.py <model.gguf> <trace.txt> <layer> [tolerance]

Trace format: STEP=0 VEC=LAYER_<layer>_<NAME> N=<n> followed by value lines.
"""
import re
import struct
import sys

import numpy as np

BLOCK_Q4K = 144          # 2 fp16 d + 2 fp16 dmin + 12 scales + 128 qs
VALUES_PER_BLOCK = 256


def f16_scalar(h):
    s = -1.0 if h & 0x8000 else 1.0
    e = (h >> 10) & 0x1F
    fr = h & 0x3FF
    if e == 0:
        return s * fr * 2.0 ** -24
    return s * (1.0 + fr / 1024.0) * 2.0 ** (e - 15)


F16_TAB = np.array([f16_scalar(i) for i in range(65536)], dtype=np.float32)


def parse_header(path):
    """Walk GGUF metadata to the tensor directory; return (tinfos, data_start)."""
    f = open(path, "rb")
    f.read(4)                                        # magic
    struct.unpack("<I", f.read(4))                    # version
    n_tensors = struct.unpack("<Q", f.read(8))[0]
    n_kv = struct.unpack("<Q", f.read(8))[0]

    def read_str(fh):
        n = struct.unpack("<Q", fh.read(8))[0]
        return fh.read(n).decode("utf-8", "replace")

    def skip_value(fh, t, et=0):
        if t == 8:
            read_str(fh)
        elif t in (0, 1, 7):
            fh.seek(1, 1)
        elif t in (2, 3):
            fh.seek(2, 1)
        elif t in (4, 5, 6):
            fh.seek(4, 1)
        elif t in (10, 11, 12):
            fh.seek(8, 1)
        elif t == 9:
            et = struct.unpack("<I", fh.read(4))[0]
            n = struct.unpack("<Q", fh.read(8))[0]
            for _ in range(n):
                skip_value(fh, et, et)
        else:
            raise ValueError("unsupported GGUF value type %d" % t)

    for _ in range(n_kv):
        read_str(f)
        t = struct.unpack("<I", f.read(4))[0]
        skip_value(f, t)

    tinfos = {}
    for _ in range(n_tensors):
        name = read_str(f)
        nd = struct.unpack("<I", f.read(4))[0]
        dims = struct.unpack("<" + "Q" * nd, f.read(8 * nd))
        ttype = struct.unpack("<I", f.read(4))[0]
        off = struct.unpack("<Q", f.read(8))[0]
        tinfos[name] = (dims, ttype, off)

    data_start = (f.tell() + 31) // 32 * 32
    f.close()
    return tinfos, data_start


def unpack_scales_mins(s):
    """llama.cpp get_scale_min_k4: 8 scales + 8 minimums from 12 packed bytes.

    s is (rows, 12) int64. Returns (sc, mn), each (rows, 8).
    """
    rows = s.shape[0]
    sc = np.zeros((rows, 8), dtype=np.int64)
    mn = np.zeros((rows, 8), dtype=np.int64)
    for j in range(8):
        if j < 4:
            sc[:, j] = s[:, j] & 0x3F
            mn[:, j] = s[:, j + 4] & 0x3F
        else:
            sc[:, j] = (s[:, j + 4] & 0x0F) | ((s[:, j - 4] >> 6) << 4)
            mn[:, j] = (s[:, j + 4] >> 4) | ((s[:, j] & 0x3F) << 4)
    return sc, mn


def deq_q4k(path, tinfos, data_start, name):
    """Full dequantization of a Q4_K tensor. Returns (out_rows, in_cols) float64.

    GGUF stores dims as (ne0, ne1) in column-major order: ne0 is the input
    width, ne1 is the number of output rows. Each row is ne0/256 blocks of 144
    bytes, and EVERY block carries its own d, dmin and 12 scale bytes. Reading
    only the first block and broadcasting its scales across the row dequantizes
    a single block and leaves the rest of every row uninitialized.
    """
    dims, _ttype, off = tinfos[name]
    ne0, ne1 = dims[0], dims[1]
    if ne0 % VALUES_PER_BLOCK:
        raise ValueError("%s: ne0=%d not a multiple of 256" % (name, ne0))
    ncol = ne0 // VALUES_PER_BLOCK
    row_bytes = ncol * BLOCK_Q4K

    f = open(path, "rb")
    f.seek(data_start + off)
    raw = np.frombuffer(f.read(ne1 * row_bytes), dtype=np.uint8)
    f.close()
    raw = raw.reshape(ne1, ncol, BLOCK_Q4K)

    out = np.empty((ne1, ne0), dtype=np.float64)
    for b in range(ncol):
        blk = raw[:, b, :]                                     # (ne1, 144)
        d = F16_TAB[blk[:, 0:2].copy().view("<u2").ravel()].astype(np.float64).reshape(ne1, 1)
        dmin = F16_TAB[blk[:, 2:4].copy().view("<u2").ravel()].astype(np.float64).reshape(ne1, 1)
        sc, mn = unpack_scales_mins(blk[:, 4:16].astype(np.int64))
        q = blk[:, 16:144].reshape(ne1, 8, 16).astype(np.int64)
        for g in range(8):
            srow = (d[:, 0] * sc[:, g])[:, None]
            mrow = (dmin[:, 0] * mn[:, g])[:, None]
            qg = q[:, g, :]
            o = b * VALUES_PER_BLOCK + g * 32
            out[:, o:o + 16] = srow * (qg & 0x0F) - mrow
            out[:, o + 16:o + 32] = srow * (qg >> 4) - mrow
    return out


def parse_vecs(path, layer):
    """Collect STEP=0 VEC=LAYER_<layer>_<NAME> full-vector records."""
    pat = re.compile(r"STEP=0 VEC=LAYER_%d_(\S+) N=(\d+)" % layer)
    vecs = {}
    cur = None
    buf = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            m = pat.match(line)
            if m:
                if cur is not None:
                    vecs.setdefault(cur, np.asarray(buf, dtype=np.float64))
                cur = m.group(1)
                buf = []
                continue
            if cur is not None and re.fullmatch(r"-?[0-9.eE+,\-]+", line):
                buf.extend(float(v) for v in line.split(","))
    if cur is not None:
        vecs.setdefault(cur, np.asarray(buf, dtype=np.float64))
    return vecs


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    model, trace, layer = sys.argv[1], sys.argv[2], int(sys.argv[3])
    tol = float(sys.argv[4]) if len(sys.argv) > 4 else 2e-2

    tinfos, data_start = parse_header(model)
    vecs = parse_vecs(trace, layer)
    if not vecs:
        print("GATE=LOGITS_PARITY_001")
        print("LAYER=%d" % layer)
        print("ORACLE=HOLD REASON=no VEC records for layer %d in trace" % layer)
        return 1

    x = vecs.get("FFN_NORM")
    if x is None:
        print("GATE=LOGITS_PARITY_001")
        print("ORACLE=HOLD REASON=FFN_NORM vector absent; cannot form the input")
        return 1

    rows = []
    failures = []
    adjudicable = 0

    # Each projection is x @ W^T, recomputed from GGUF bytes by numpy.
    for tensor, key in (("blk.%d.ffn_gate.weight" % layer, "FFN_GATE"),
                        ("blk.%d.ffn_up.weight" % layer, "FFN_UP")):
        if tensor not in tinfos or key not in vecs:
            rows.append((key, "NOT_ADJUDICATED", "missing tensor or trace vector"))
            continue
        W = deq_q4k(model, tinfos, data_start, tensor)
        if W.shape[0] != len(vecs[key]) or W.shape[1] != len(x):
            rows.append((key, "NOT_ADJUDICATED",
                         "shape mismatch W=%s x=%d got=%d" % (W.shape, len(x), len(vecs[key]))))
            continue
        ref = W @ x
        got = vecs[key]
        denom = np.max(np.abs(ref))
        if denom == 0.0:
            rows.append((key, "NOT_ADJUDICATED", "oracle output is identically zero"))
            continue
        rel = float(np.max(np.abs(got - ref)) / denom)
        adjudicable += 1
        status = "PASS" if rel < tol else "FAIL"
        rows.append((key, status, "rel_err=%.6g tol=%.3g" % (rel, tol)))
        if status == "FAIL":
            failures.append((key, rel))

    # The activation is a pointwise function of the two projections. It checks
    # the trace against ITSELF, not against the oracle, so it is reported
    # separately and never contributes to the oracle verdict.
    g, u, s = vecs.get("FFN_GATE"), vecs.get("FFN_UP"), vecs.get("SWIGLU")
    sw_status, sw_note = "NOT_ADJUDICATED", "missing trace vector"
    if g is not None and u is not None and s is not None:
        self_ref = (g / (1.0 + np.exp(-g))) * u
        d = float(np.max(np.abs(self_ref - s)) / max(np.max(np.abs(s)), 1e-30))
        sw_status = "SELF_CONSISTENT" if d < 1e-5 else "SELF_INCONSISTENT"
        sw_note = "rel=%.3g (trace vs trace, NOT oracle adjudication)" % d

    print("=" * 79)
    print("RAWRXD CERTIFICATION RECORD")
    print("=" * 79)
    print()
    print("GATE=LOGITS_PARITY_001")
    print("LAYER=%d" % layer)
    print("MODEL=%s" % model)
    print("TRACE=%s" % trace)
    print("ORACLE=scripts/q4k_oracle_gate.py (numpy, no Deep2 linkage)")
    print("ORACLE_INDEPENDENT=yes (reads GGUF bytes directly, links no engine)")
    print("TOLERANCE=%g" % tol)
    print()
    print("-" * 79)
    print("ORACLE COMPARISON")
    print("-" * 79)
    for key, status, note in rows:
        print("  %-9s %-16s %s" % (key, status, note))
    print("  %-9s %-16s %s" % ("SWIGLU", sw_status, sw_note))
    print()
    print("SURFACES_ADJUDICATED=%d" % adjudicable)
    print("NOT_ADJUDICATED=%d" % (len(rows) - adjudicable))
    print()
    print("-" * 79)
    print("SCOPE")
    print("-" * 79)
    print("  This gate covers the two Q4_K FFN projections at one layer. It does")
    print("  NOT adjudicate attention, RoPE, the residual stream, final norm,")
    print("  logits, or any other layer. A PASS means no divergence was found in")
    print("  the covered surfaces, not that Deep2 is numerically correct overall.")
    print()
    print("=" * 79)
    if not adjudicable:
        print("VERDICT=HOLD REASON=no surface could be adjudicated")
        print("=" * 79)
        return 1
    if failures:
        print("FIRST_MISMATCH=%s rel=%.6g" % (failures[0][0], failures[0][1]))
        print("VERDICT=FAIL")
        print("=" * 79)
        return 1
    print("VERDICT=PASS (scoped: see SCOPE section)")
    print("=" * 79)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
