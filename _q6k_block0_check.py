#!/usr/bin/env python3
"""Block-0 verification: does vec_dot aux8 ordering match dequant value order?"""
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
t = tinfos["blk.4.ffn_down.weight"]
rows, cols = t[0][1], t[0][0]
bpr = cols // 256
f = open(m.GGUF, "rb")
f.seek(ds + t[2])
raw = np.frombuffer(f.read(rows * bpr * 210), dtype=np.uint8).reshape(rows, -1)
f.close()
blk = raw[0][0:210]

d = float(m.F16_TAB[struct.unpack("<H", blk[208:210])[0]])
ql = blk[0:128].astype(np.int64)
qh = blk[128:192].astype(np.int64)
sc = np.frombuffer(blk[192:208], dtype=np.int8).astype(np.int64)
xb = sw[0:256]
idx = int(np.argmax(np.abs(xb)))
iscale = -127.0 / xb[idx]
yq = np.clip(np.round(iscale * xb).astype(np.int64), -127, 127)
yd = 1.0 / iscale

# canonical dequant (value order): y[half*128 + l] etc.
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

# vec_dot aux8 build (engine order)
aux8 = np.empty(256, dtype=np.int64)
for half in range(2):
    for l in range(32):
        aux8[half * 128 + l] = ((ql[l] & 0xF) | ((qh[l] & 3) << 4)) - 32
        aux8[half * 128 + l + 32] = ((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32
        aux8[half * 128 + l + 64] = ((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32
        aux8[half * 128 + l + 96] = ((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32

# check consistency: vals[k] should equal d * sc[group(k)] * (aux8[k] + 32) for the
# corresponding scale group used in vec_dot (groups of 16, is++ sequential)
consistent = True
for k in range(256):
    # find the group the vec_dot uses: group = k // 16
    g = k // 16
    implied = d * sc[g] * (aux8[k] + 32)
    if abs(implied - vals[k]) > 1e-6 * max(1.0, abs(vals[k])):
        consistent = False
        if k < 12:
            print(f"k={k}: vals={vals[k]:.4f} implied={implied:.4f} g={g} sc[g]={sc[g]} aux8={aux8[k]}")
print("dequant/vecdot order consistent:", consistent)

# float dot vs engine vec_dot sim on block 0
aux32 = np.zeros(8, dtype=np.int64)
for j in range(16):
    scale = sc[j]
    seg_q = yq[j * 16:(j + 1) * 16]
    seg_a = aux8[j * 16:(j + 1) * 16]
    prod = (seg_q * seg_a).reshape(2, 8).sum(axis=0)
    aux32 += scale * prod
sim0 = d * yd * float(aux32.sum())
fdot = float(np.dot(vals, xb))
print("block0 vecdot-sim:", sim0)
print("block0 float dot :", fdot)
print("yq range:", yq.min(), yq.max(), "yd:", yd)
print("sw range:", sw.min(), sw.max())