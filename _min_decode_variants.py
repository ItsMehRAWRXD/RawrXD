#!/usr/bin/env python3
"""Verify min-decode variants against llama.cpp canonical for block 0."""
import importlib.util
import struct

import numpy as np

spec = importlib.util.spec_from_file_location(
    "l4", r"F:\~dev\rawrxd\scripts\qwen2_l4_reference.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

tinfos, ds = m.parse_header(m.GGUF)
NAME = "blk.4.ffn_gate.weight"
t = tinfos[NAME]
rows, cols = t[0][1], t[0][0]
bpr = cols // 256
f = open(m.GGUF, "rb")
f.seek(ds + t[2])
raw = np.frombuffer(f.read(rows * bpr * 144), dtype=np.uint8).reshape(rows, -1)
f.close()
s = raw[0][4:16].astype(np.int64)

print("raw scale bytes:", s)

# Variant A: my earlier (wrong) one: m=(q[j+4]>>4)|((q[j]&0x3F)<<4)
va = np.zeros(8, dtype=np.int64)
# Variant B (llama get_scale_min_k4 EXACT): m=(q[j+4]>>4)|((q[j]&0xF)<<4)
vb = np.zeros(8, dtype=np.int64)
# Variant C (engine utmp dance)
k1, k2, k3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303
u0 = int.from_bytes(raw[0][4:8], "little")
u1 = int.from_bytes(raw[0][8:12], "little")
u2 = int.from_bytes(raw[0][12:16], "little")
ut = [u0, u1, u2, 0]
ut[3] = ((ut[2] >> 4) & k2) | (((ut[1] >> 6) & k3) << 4)
uaux = ut[1] & k1
ut[1] = (ut[2] & k2) | (((ut[0] >> 6) & k3) << 4)
ut[2] = uaux
ut[0] &= k1
vc = np.frombuffer(ut[2].to_bytes(4, "little") + ut[3].to_bytes(4, "little"),
                   dtype=np.uint8).astype(np.int64)

for j in range(8):
    if j < 4:
        vb[j] = s[j + 4] & 63
    else:
        vb[j] = (s[j + 4] >> 4) | ((s[j] & 0xF) << 4)
    va[j] = (s[j + 4] >> 4) | ((s[j] & 0x3F) << 4) if j >= 4 else (s[j + 4] & 63)

print("variantA (6-bit shift):", va)
print("variantB (llama exact):", vb)
print("variantC (utmp dance) :", vc[:8])
print()
print("utmp[0..3] after mask:", [hex(u) for u in ut])