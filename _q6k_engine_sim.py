#!/usr/bin/env python3
"""Simulate the engine's gemv_q6_k_scalar hot path (Q8K-quantized activation +
canonical vec_dot_q6_K_q8_K) on blk.4.ffn_down with the engine's own SWIGLU
vector, and compare to the engine's FFN_DOWN output rows 0..2."""
import importlib.util
import struct

import numpy as np

spec = importlib.util.spec_from_file_location(
    "l4", r"F:\~dev\rawrxd\scripts\qwen2_l4_reference.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

tinfos, ds = m.parse_header(m.GGUF)
vecs = m.parse_vecs()
sw = vecs["SWIGLU"].astype(np.float64)
got_down = vecs["FFN_DOWN"]
NAME = "blk.4.ffn_down.weight"
t = tinfos[NAME]
rows, cols = t[0][1], t[0][0]
bpr = cols // 256
f = open(m.GGUF, "rb")
f.seek(ds + t[2])
raw = np.frombuffer(f.read(rows * bpr * 210), dtype=np.uint8).reshape(rows, -1)
f.close()

k1 = 0x3F3F3F3F


def q8k_block(xb):
    idx = int(np.argmax(np.abs(xb)))
    mx = xb[idx]
    if mx == 0:
        return 0.0, np.zeros(256, dtype=np.int64), np.zeros(16, dtype=np.int64)
    iscale = -127.0 / mx
    v = np.clip(np.round(iscale * xb).astype(np.int64), -127, 127)
    return 1.0 / iscale, v, v.reshape(16, 16).sum(axis=1)


def engine_q6k_dot_row(row_bytes, x):
    total = 0.0
    for b in range(bpr):
        blk = row_bytes[b * 210:(b + 1) * 210]
        d = float(m.F16_TAB[struct.unpack("<H", blk[208:210])[0]])
        ql = blk[0:128].astype(np.int64)
        qh = blk[128:192].astype(np.int64)
        sc = np.frombuffer(blk[192:208], dtype=np.int8).astype(np.int64)
        aux8 = np.empty(256, dtype=np.int64)
        for half in range(2):
            for l in range(32):
                aux8[half * 128 + l] = ((ql[l] & 0xF) | ((qh[l] & 3) << 4)) - 32
                aux8[half * 128 + l + 32] = ((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32
                aux8[half * 128 + l + 64] = ((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32
                aux8[half * 128 + l + 96] = ((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32
        yd, yq, yb = q8k_block(x[b * 256:(b + 1) * 256])
        aux32 = np.zeros(8, dtype=np.int64)
        for j in range(16):
            scale = sc[j]
            seg_q = yq[j * 16:(j + 1) * 16]
            seg_a = aux8[j * 16:(j + 1) * 16]
            prod = (seg_q * seg_a).reshape(2, 8).sum(axis=0)
            aux32 += scale * prod
        total += d * yd * float(aux32.sum())
    return total


def canonical_dot_row(row_bytes, x):
    return None


def canonical_dot_row(row_bytes, x):
    total = 0.0
    for b in range(bpr):
        blk = row_bytes[b * 210:(b + 1) * 210]
        d = float(m.F16_TAB[struct.unpack("<H", blk[208:210])[0]])
        ql = blk[0:128].astype(np.int64)
        qh = blk[128:192].astype(np.int64)
        sc = np.frombuffer(blk[192:208], dtype=np.int8).astype(np.int64)
        vals = np.empty(256, dtype=np.float64)
        for half in range(2):
            for l in range(32):
                isx = l // 16
                q1 = ((ql[l] & 0xF) | ((qh[l] & 3) << 4)) - 32
                q2 = ((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32
                q3 = ((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32
                q4 = ((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32
                vals[half * 128 + l] = d * sc[isx + 0] * q1
                vals[half * 128 + l + 32] = d * sc[isx + 2] * q2
                vals[half * 128 + l + 64] = d * sc[isx + 4] * q3
                vals[half * 128 + l + 96] = d * sc[isx + 6] * q4
        total += float(np.dot(vals, x[b * 256:(b + 1) * 256]))
    return total


for r in range(3):
    row = raw[r]
    sim = engine_q6k_dot_row(row, sw)
    canon = canonical_dot_row(row, sw)
    print(f"row{r}: engine={got_down[r]:.4f} intSim={sim:.4f} floatRef={canon:.4f}")