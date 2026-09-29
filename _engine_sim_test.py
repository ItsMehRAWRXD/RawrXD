#!/usr/bin/env python3
"""Simulate the engine's exact Q4K hot path (quantize_row_q8_K + masked
vec_dot_q4_K_q8_K) in Python on the real blk.4.ffn_gate bytes with the
oracle's FFN_NORM input, and compare to the oracle's FFN_GATE output."""
import importlib.util
import struct

import numpy as np

spec = importlib.util.spec_from_file_location(
    "l4", r"F:\~dev\rawrxd\scripts\qwen2_l4_reference.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

tinfos, ds = m.parse_header(m.GGUF)
vecs = m.parse_vecs()
x = vecs["FFN_NORM"].astype(np.float64)
got = vecs["FFN_GATE"]
NAME = "blk.4.ffn_gate.weight"
t = tinfos[NAME]
rows, cols = t[0][1], t[0][0]
blocks_per_row = cols // 256
row_bytes = blocks_per_row * 144

f = open(m.GGUF, "rb")
f.seek(ds + t[2])
raw = np.frombuffer(f.read(rows * row_bytes), dtype=np.uint8).reshape(rows, -1)
f.close()

k1, k2, k3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303


def q8k_block(xb):
    amax_idx = int(np.argmax(np.abs(xb)))
    amax_signed = xb[amax_idx]
    iscale = -127.0 / amax_signed
    v = np.round(iscale * xb).astype(np.int64)
    v = np.clip(v, -127, 127)
    d = 1.0 / iscale
    bsums = v.reshape(16, 16).sum(axis=1)
    return d, v, bsums


def engine_dot_row(row_bytes_buf, x):
    total = 0.0
    for b in range(blocks_per_row):
        blk = row_bytes_buf[b * 144:(b + 1) * 144]
        d16, dmin16 = struct.unpack("<HH", blk[0:4])
        dv = float(m.F16_TAB[d16])
        dminv = float(m.F16_TAB[dmin16])
        u0 = int.from_bytes(blk[4:8], "little")
        u1 = int.from_bytes(blk[8:12], "little")
        u2 = int.from_bytes(blk[12:16], "little")
        ut = [u0, u1, u2, 0]
        ut[3] = ((ut[2] >> 4) & k2) | (((ut[1] >> 6) & k3) << 4)
        uaux = ut[1] & k1
        ut[1] = (ut[2] & k2) | (((ut[0] >> 6) & k3) << 4)
        ut[2] = uaux
        ut[0] &= k1
        # Engine hot path uses 8 scales + 8 mins (one per 32-value sub-block).
        sc = np.frombuffer(ut[0].to_bytes(4, "little")
                           + ut[1].to_bytes(4, "little"),
                           dtype=np.uint8).astype(np.int64)[:8]
        mn = np.frombuffer(ut[2].to_bytes(4, "little")
                           + ut[3].to_bytes(4, "little"),
                           dtype=np.uint8).astype(np.int64)[:8]
        q4 = np.frombuffer(blk[16:144], dtype=np.uint8).astype(np.int64)
        a = np.empty(256, dtype=np.int64)
        for j in range(4):
            a[j * 64:j * 64 + 32] = q4[j * 32:j * 32 + 32] & 0xF
            a[j * 64 + 32:j * 64 + 64] = q4[j * 32:j * 32 + 32] >> 4
        xb = x[b * 256:(b + 1) * 256]
        yd, yq, yb = q8k_block(xb)
        sumi = int(np.sum(yb * np.repeat(mn, 2)))
        sumf = 0.0
        for j in range(8):
            scale = sc[j]
            sumf += scale * int(np.sum(yq[j * 32:(j + 1) * 32] * a[j * 32:(j + 1) * 32]))
        total += dv * yd * sumf
        total -= dminv * yd * sumi
    return total


sim0 = engine_dot_row(raw[0], x)
sim1 = engine_dot_row(raw[1], x)
print("oracle got[0]:", got[0], "engine-sim[0]:", sim0)
print("oracle got[1]:", got[1], "engine-sim[1]:", sim1)

# canonical float reference for comparison
W = m.deq_q4k(m.GGUF, tinfos, ds, NAME)
ref = W @ x
print("canonical ref[0]:", ref[0], "ref[1]:", ref[1])
print("corr(got, canonical):", float(np.corrcoef(got[:1000], ref[:1000])[0, 1]))