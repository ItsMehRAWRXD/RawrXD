#!/usr/bin/env python3
"""Per-block isolation: engine sim vs canonical for block 0 of L4 gate."""
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
NAME = "blk.4.ffn_gate.weight"
t = tinfos[NAME]
rows, cols = t[0][1], t[0][0]
bpr = cols // 256
f = open(m.GGUF, "rb")
f.seek(ds + t[2])
raw = np.frombuffer(f.read(rows * bpr * 144), dtype=np.uint8).reshape(rows, -1)
f.close()
blk = raw[0][0:144]

d16, dmin16 = struct.unpack("<HH", blk[0:4])
dv = float(m.F16_TAB[d16])
dminv = float(m.F16_TAB[dmin16])
k1, k2, k3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303
u0 = int.from_bytes(blk[4:8], "little")
u1 = int.from_bytes(blk[8:12], "little")
u2 = int.from_bytes(blk[12:16], "little")
ut = [u0, u1, u2, 0]
ut[3] = ((ut[2] >> 4) & k2) | (((ut[1] >> 6) & k3) << 4)
uaux = ut[1] & k1
ut[1] = (ut[2] & k2) | (((ut[0] >> 6) & k3) << 4)
ut[2] = uaux
ut[0] &= k1
sc8 = np.frombuffer(ut[0].to_bytes(4, "little") + ut[1].to_bytes(4, "little"),
                    dtype=np.uint8).astype(np.int64)[:8]
mn8 = np.frombuffer(ut[2].to_bytes(4, "little") + ut[3].to_bytes(4, "little"),
                    dtype=np.uint8).astype(np.int64)[:8]

csc8 = np.zeros(8, dtype=np.int64)
cmn8 = np.zeros(8, dtype=np.int64)
s = blk[4:16].astype(np.int64)
for j in range(8):
    if j < 4:
        csc8[j] = s[j] & 63
        cmn8[j] = s[j + 4] & 63
    else:
        csc8[j] = (s[j + 4] & 0xF) | ((s[j - 4] >> 6) << 4)
        cmn8[j] = (s[j + 4] >> 4) | ((s[j] & 0x3F) << 4)

q4 = np.frombuffer(blk[16:144], dtype=np.uint8).astype(np.int64)
a = np.empty(256, dtype=np.int64)
for j in range(4):
    a[j * 64:j * 64 + 32] = q4[j * 32:j * 32 + 32] & 0xF
    a[j * 64 + 32:j * 64 + 64] = q4[j * 32:j * 32 + 32] >> 4

cvals = np.empty(256, dtype=np.float64)
for isb in range(8):
    srow = dv * csc8[isb]
    mrow = dminv * cmn8[isb]
    cvals[isb * 32:isb * 32 + 16] = srow * (q4[isb * 16:isb * 16 + 16] & 0xF) - mrow
    cvals[isb * 32 + 16:isb * 32 + 32] = srow * (q4[isb * 16:isb * 16 + 16] >> 4) - mrow

xb = x[0:256]
amax_idx = int(np.argmax(np.abs(xb)))
iscale = -127.0 / xb[amax_idx]
yq = np.clip(np.round(iscale * xb).astype(np.int64), -127, 127)
yd = 1.0 / iscale
yb = yq.reshape(16, 16).sum(axis=1)

sumi = int(np.sum(yb * np.repeat(mn8, 2)))
sumf = 0
for j in range(8):
    sumf += sc8[j] * int(np.sum(yq[j * 32:(j + 1) * 32] * a[j * 32:(j + 1) * 32]))
simb = dv * yd * sumf - dminv * yd * sumi
canonb = float(np.dot(cvals, xb))

print("block0 engine-sim:", simb)
print("block0 canonical :", canonb)
print("scale decode match:", bool(np.array_equal(sc8, csc8)))
print("min   decode match:", bool(np.array_equal(mn8, cmn8)))
print("engine sc8:", sc8)
print("canon csc8:", csc8)
print("engine mn8:", mn8)
print("canon cmn8:", cmn8)
# also compare nibble groupings: canonical value layout vs engine a[]
nib_match = True
for isb in range(8):
    lo = q4[isb * 16:isb * 16 + 16] & 0xF
    hi = q4[isb * 16:isb * 16 + 16] >> 4
    e_lo = a[isb * 32:isb * 32 + 16]
    e_hi = a[isb * 32 + 16:isb * 32 + 32]
    if not (np.array_equal(lo, e_lo) and np.array_equal(hi, e_hi)):
        nib_match = False
print("nibble layout match:", nib_match)