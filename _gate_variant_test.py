#!/usr/bin/env python3
"""Decisive: test whether engine gate output matches dequant variants
(add-min vs subtract-min) and nibble orderings for blk.4.ffn_gate."""
import importlib.util
import struct

import numpy as np

spec = importlib.util.spec_from_file_location(
    "l4", r"F:\~dev\rawrxd\scripts\qwen2_l4_reference.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

import numpy as np  # noqa: E402

tinfos, ds = m.parse_header(m.GGUF)
vecs = m.parse_vecs()
got = vecs["FFN_GATE"]
x = vecs["FFN_NORM"]
NAME = "blk.4.ffn_gate.weight"


def deq_variant(name, sign, hi_first=False):
    t = tinfos[name]
    off = t[2]
    rows, cols = t[0][1], t[0][0]
    row_bytes = (cols // 256) * 144
    f = open(m.GGUF, "rb")
    f.seek(ds + off)
    raw = np.frombuffer(f.read(rows * row_bytes), dtype=np.uint8).reshape(rows, row_bytes)
    f.close()
    d = np.frombuffer(raw[:, 0:2].tobytes(), dtype="<u2")
    dmin = np.frombuffer(raw[:, 2:4].tobytes(), dtype="<u2")
    dv = m.F16_TAB[d].reshape(rows, 1).astype(np.float64)
    dminv = m.F16_TAB[dmin].reshape(rows, 1).astype(np.float64)
    sc = np.zeros((rows, 8), dtype=np.int64)
    mn = np.zeros((rows, 8), dtype=np.int64)
    s = raw[:, 4:16].astype(np.int64)
    for j in range(8):
        if j < 4:
            sc[:, j] = s[:, j] & 63
            mn[:, j] = s[:, j + 4] & 0x3F
        else:
            sc[:, j] = (s[:, j + 4] & 0xF) | ((s[:, j - 4] >> 6) << 4)
            mn[:, j] = (s[:, j + 4] >> 4) | ((s[:, j] & 0x3F) << 4)
    qs = raw[:, 16:144].reshape(rows, 8, 16).astype(np.int64)
    vals = np.empty((rows, cols), dtype=np.float64)
    for isb in range(8):
        srow = dv[:, 0] * sc[:, isb]
        mrow = dminv[:, 0] * mn[:, isb]
        qsub = qs[:, isb, :]
        lo = qsub & 0xF
        hi = qsub >> 4
        if hi_first:
            lo, hi = hi, lo
        vals[:, isb * 32:isb * 32 + 16] = srow[:, None] * lo + sign * mrow[:, None]
        vals[:, isb * 32 + 16:isb * 32 + 32] = srow[:, None] * hi + sign * mrow[:, None]
    return vals


for sign, slabel in ((-1.0, "SUB"), (+1.0, "ADD")):
    for hi_first, hlabel in ((False, "loHi"), (True, "hiLo")):
        W = deq_variant(NAME, sign, hi_first)
        ref = W @ x
        n = 1000
        corr = float(np.corrcoef(got[:n], ref[:n])[0, 1])
        rel = float(np.max(np.abs(got[:n] - ref[:n])) / np.max(np.abs(ref[:n])))
        print(f"{slabel}/{hlabel}: corr={corr:.4f} rel_err={rel:.4g}")

print("got mean/std:", got.mean(), got.std())