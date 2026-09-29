#!/usr/bin/env python3
"""Directly verify: reference Q4K dot with the EXACT oracle x (FFN_NORM trace)
against the oracle's FFN_GATE output, row by row, for rows 0..7 — but using
only the FIRST 8 outputs we have. If canonical matches oracle got for the
oracle's own x, the engine kernel is fine and my C test x differs — if canonical
does NOT match the oracle either, the oracle GEMV input differs from FFN_NORM.

Also tests a transposed-weight hypothesis: ref = x @ W (instead of W @ x).
"""
import importlib.util
import numpy as np

spec = importlib.util.spec_from_file_location(
    "l4", r"F:\~dev\rawrxd\scripts\qwen2_l4_reference.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

tinfos, ds = m.parse_header(m.GGUF)
vecs = m.parse_vecs()
x = vecs["FFN_NORM"]           # engine's declared GEMV input (5120)
got = vecs["FFN_GATE"]         # engine output (27648)

W = m.deq_q4k(m.GGUF, tinfos, ds, "blk.4.ffn_gate.weight")  # (27648, 5120)

ref_norm = W @ x
print("oracle got[0:4]  :", got[:4])
print("W@x [0:4]        :", ref_norm[:4])

# Transposed hypothesis: engine computed x @ W.T using W stored (in=5120 rows?)
# In GGUF order dims (5120, 27648): engine may treat rows/cols swapped.
# W_T interpretation: dequant gives (27648, 5120); if engine reads it as (5120,27648)
# then its 'rows' for outDim=27648 works only if transposed correctly.
# Test: ref_transposed = x @ W_as_stored where W_as_stored = deq reshaped (5120, 27648)?
# Equivalent: deq tensor bytes are rows-major over OUT rows; a transpose bug means
# engine dot uses byte-row r but treats blocks as columns. Emulate:
# got[i] should equal sum_j W[j, i] * x[j] — that is x @ W.
ref_T = x @ W.T  # (27648,)
print("x@W.T [0:4]      :", ref_T[:4])
print("corr(got, W@x)   :", float(np.corrcoef(got[:1000], ref_norm[:1000])[0, 1]))
print("corr(got, x@W.T) :", float(np.corrcoef(got[:1000], ref_T[:1000])[0, 1]))

# Constant-output hypothesis: got ≈ c (mean -3.879, std 1.14). Check autocorr lag1:
print("got lag1 autocorr:", float(np.corrcoef(got[:-1], got[1:])[0, 1]))
# Distribution: ref vs got quantiles
print("got p1/p50/p99:", np.percentile(got, [1, 50, 99]))
print("ref p1/p50/p99:", np.percentile(ref_norm, [1, 50, 99]))