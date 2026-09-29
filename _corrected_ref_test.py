#!/usr/bin/env python3
"""Definitive: compute canonical dot with the utmp-dance decode (both 6-bit mins,
matching llama's own vec_dot), compare with the engine kernel output."""
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
t = tinfos["blk.4.ffn_gate.weight"]
rows, cols = t[0][1], t[0][0]
bpr = cols // 256
f = open(m.GGUF, "rb")
f.seek(ds + t[2])
raw = np.frombuffer(f.read(rows * bpr * 144), dtype=np.uint8).reshape(rows, -1)
f.close()

k1, k2, k3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303


def deq_row(rowbytes):
    out = np.empty(256 * bpr, dtype=np.float64)
    for b in range(bpr):
        blk = rowbytes[b * 144:(b + 1) * 144]
        d = float(m.F16_TAB[struct.unpack("<H", blk[0:2])[0]])
        dmin = float(m.F16_TAB[struct.unpack("<H", blk[2:4])[0]])
        sb = blk[4:16]
        u = list(struct.unpack("<III", bytes(sb))) + [0]
        u[3] = ((u[2] >> 4) & k2) | (((u[1] >> 6) & k3) << 4)
        uaux = u[1] & k1
        u[1] = (u[2] & k2) | (((u[0] >> 6) & k3) << 4)
        u[2] = uaux
        u[0] &= k1
        sc = np.frombuffer(struct.pack("<II", u[0], u[1]), dtype=np.uint8).astype(np.int64)
        mn = np.frombuffer(struct.pack("<II", u[2], u[3]), dtype=np.uint8).astype(np.int64)
        qs = blk[16:144].astype(np.int64)
        for isb in range(8):
            s = d * sc[isb]
            mv = dmin * mn[isb]
            out[isb * 32:isb * 32 + 16] = s * (qs[isb * 16:isb * 16 + 16] & 0xF) - mv
            out[isb * 32 + 16:isb * 32 + 32] = s * (qs[isb * 16:isb * 16 + 16] >> 4) - mv
    return out


got = [-4.53685379, -4.52666044, -4.48861551, -2.29625702,
       -4.92178535, -2.61954975, -3.679111, -3.85969925]
print("row | dance-decode float dot | engine kernel")
for r in range(8):
    vals = deq_row(raw[r])
    ref = float(np.dot(vals, x))
    rel = abs(got[r] - ref) / max(1e-9, abs(ref))
    print(f"row{r}: ref={ref:.4f} kernel={got[r]:.4f} rel={rel:.4f}")