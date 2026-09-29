#!/usr/bin/env python3
"""DEEP2_QWEN2_CPU_CORRECTNESS_001 — attn_q (Q4_K) triple adjudication.

For rows 0..3 of blk.4.attn_q.weight, computes:
  A  canonical float dequant dot  (llama dequantize_row_q4_K: 32 lo then 32 hi
     nibbles per 64-chunk; scales via get_scale_min_k4)
  B  canonical ggml int-dot      (vec_dot_q4_K_q8_K: Q8K-quantized activation,
     utmp scale decode, 16lo+16hi sub-block nibbles)
  C  engine reported value       (from the fixed oracle trace)

If B == C != A: the engine's kernel is ggml-faithful and the divergence
elsewhere. If A == B != C: the engine kernel is broken. If A != B: the two
ggml paths themselves disagree on this machine's transcription -> the nibble
grouping in one of the two decodes is wrong.
"""
import importlib.util
import struct

import numpy as np

spec = importlib.util.spec_from_file_location(
    "l4", r"F:\~dev\rawrxd\scripts\qwen2_l4_reference.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

t, ds = m.parse_header(m.GGUF)
vecs = m.parse_vecs()
x = vecs["ATTN_NORM"].astype(np.float64).ravel()
gotQ = vecs["Q"].astype(np.float64).ravel()

NAME = "blk.4.attn_q.weight"
dims, ttype, off = t[NAME]
ne0, ne1 = dims[0], dims[1]
bpr = ne0 // 256
rb = bpr * 144
with open(m.GGUF, "rb") as f:
    f.seek(ds + off)
    raw = np.frombuffer(f.read(ne1 * rb), dtype=np.uint8).reshape(ne1, rb)


def get_scale_min(j, s):
    if j < 4:
        return s[j] & 63, s[j + 4] & 63
    return (s[j + 4] & 0xF) | ((s[j - 4] >> 6) << 4), (s[j + 4] >> 4) | ((s[j] & 0x3F) << 4)


def dequant_A(row):
    """llama dequantize_row_q4_K: nibbles grouped 32 lo + 32 hi per 64 chunk."""
    vals = np.empty(ne0, dtype=np.float64)
    for b in range(bpr):
        blk = row[b * 144:(b + 1) * 144]
        d = float(m.F16_TAB[struct.unpack("<H", blk[0:2])[0]])
        dmin = float(m.F16_TAB[struct.unpack("<H", blk[2:4])[0]])
        s = blk[4:16].astype(np.int64)
        q = blk[16:144].astype(np.int64)
        for j in range(8):
            sc, mn = get_scale_min(j, s)
            base = b" "  # unused
            is_ = j
            lo = q[(is_ // 2) * 32:(is_ // 2) * 32 + 32] & 0xF if False else None
        # canonical llama: j iterates 64-value chunks; scale idx = j/32
        for chunk in range(4):
            isb = chunk * 2
            sc, mn = get_scale_min(isb, s), get_scale_min(isb, s)
        # Use llama's exact grouping: 4 chunks of 64 values; scales idx j/32
        q = blk[16:144]
        pos = 0
        for chunk in range(4):
            isb = chunk * 2
            scv, mnv = get_scale_min(isb, s)
            slo = float(m.F16_TAB[struct.unpack('<H', blk[0:2])[0]]) * scv
            mlo = float(m.F16_TAB[struct.unpack('<H', blk[2:4])[0]]) * mnv
            # 32 lo nibbles then 32 hi nibbles from the SAME 32 bytes
            seg = q[chunk * 32:(chunk + 1) * 32].astype(np.int64)
            vals[b * 256 + chunk * 64 + 0:b * 256 + chunk * 64 + 32] = slo * (seg & 0xF) - mlo
            vals[b * 256 + chunk * 64 + 32:b * 256 + chunk * 64 + 64] = slo * (seg >> 4) - mlo
    return vals


def dot_B(row_bytes, xd, xq, xb):
    """ggml vec_dot_q4_K_q8_K generic semantics."""
    total = 0.0
    for b in range(bpr):
        blk = row_bytes[b * 144:(b + 1) * 144]
        d = float(m.F16_TAB[struct.unpack("<H", blk[0:2])[0]])
        dmin = float(m.F16_TAB[struct.unpack("<H", blk[2:4])[0]])
        s = blk[4:16].astype(np.int64)
        sc = np.zeros(8, dtype=np.int64)
        mn = np.zeros(8, dtype=np.int64)
        for j in range(8):
            sc[j], mn[j] = get_scale_min(j, s)
        qs = blk[16:144].reshape(8, 16).astype(np.int64)
        yq = xq[b * 256:(b + 1) * 256]
        yd = xd[b]
        yb = xbs[b]
        sumi = int(np.sum(yb * np.repeat(mn, 2)))
        sumf = 0
        for isb in range(8):
            sub = np.concatenate([(qs[isb] & 0xF), (qs[isb] >> 4)])
            sumf += int(sc[isb]) * int(np.sum(yq[isb * 32:(isb + 1) * 32] * sub))
        total += d * yd * sumf
        total -= dmin * yd * sumi
    return total


def q8k_row(xv):
    n = len(xv)
    nb = n // 256
    yq = np.zeros(n, dtype=np.int64)
    yd = np.zeros(nb)
    yb = np.zeros((nb, 16), dtype=np.int64)
    for b in range(nb):
        xb = xv[b * 256:(b + 1) * 256]
        i = int(np.argmax(np.abs(xb)))
        mx = xb[i]
        if mx == 0:
            continue
        iscale = -127.0 / mx
        v = np.clip(np.round(iscale * xb).astype(np.int64), -127, 127)
        yq[b * 256:(b + 1) * 256] = v
        yd[b] = 1.0 / iscale
        yb[b] = v.reshape(16, 16).sum(axis=1)
    return yd, yq, yb


yd, xq, xbs = q8k_row(x)
xbs = xbs  # alias used inside dot_B


def main():
    print("GGML-canonical int-dot vs engine vs float-dequant (attn_q, Q4_K):")
    worst = 0.0
    for r in range(4):
        A = float(np.dot(dequant_A(raw[r]), x))
        B = dot_B(raw[r], yd, xq, xbs)
        C = float(gotQ[r])
        b_engine = abs(B - C)
        worst = max(worst, b_engine)
        print(f"ROW {r}: floatdequant(A)={A:+.6f}  intdot(B)={B:+.6f}  "
              f"engine(C)={C:+.6f}  |B-C|={abs(B-C):.6f}  |A-B|={abs(A-B):.4f}")
    faithful = "PASS" if worst < 0.05 else "FAIL"
    print(f"ENGINE_VS_GGML_INTDOT={faithful} (worst |B-C| = {worst:.4f})")


if __name__ == "__main__":
    main()