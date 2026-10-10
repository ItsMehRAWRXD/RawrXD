#!/usr/bin/env python3
"""Solve for OUR effective attention weights at (layer, step) from our recorded
attention output and llama.cpp's V vectors, then compare with llama.cpp's own
softmax. A 2-slot solve determines w0, w1 per head exactly (128 equations, 2
unknowns), so this recovers the weights our runtime actually used.
"""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1b"


def read_llama(name):
    raw = open(os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (STEP, name, LAYER)), "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    return ne, np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


nes, sr = read_llama("kq_soft_max")
nev, vr = read_llama("v_attn")
Soft = sr.reshape(nes[2], nes[0], nes[1])
V = vr.reshape(nev[2], nev[1], nev[0])      # [head][dim][slot]
n_kv = STEP + 1

tags = ("_l%d_" % LAYER, "_l%02d_" % LAYER)
ours = None
for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
    if "Attention_Output" not in p or ("_p%d_" % STEP) not in p:
        continue
    if not any(t in p for t in tags):
        continue
    b = open(p, "rb").read()
    cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
    ours = np.frombuffer(b[20 + 8 + 8:20 + 8 + 8 + cnt * 4],
                         dtype=np.float32).astype(np.float64).reshape(16, -1)
    break

print("layer %d step %d, n_kv=%d" % (LAYER, STEP, n_kv))
if ours is None:
    print("no recorded attention output")
    sys.exit(1)

print("\nhead   llama[w0, w1]              ours-solved[w0, w1]          sum    diff_w0")
rows = []
for h in range(16):
    A = np.stack([V[h, :, 0], V[h, :, 1]], axis=1)     # [128, 2]
    sol, res, rank, sv = np.linalg.lstsq(A, ours[h], rcond=None)
    lv = [float(Soft[h, kv][0]) for kv in range(n_kv)]
    rows.append((sol[0], sol[1], lv[0], lv[1]))
    if h < 6:
        print("h%-3d   [%.6f, %.6f]      [%.6f, %.6f]   %6.3f  %+9.6f"
              % (h, lv[0], lv[1], sol[0], sol[1], sol[0] + sol[1],
                 sol[0] - lv[0]))
w0o = np.array([r[0] for r in rows])
w1o = np.array([r[1] for r in rows])
w0l = np.array([r[2] for r in rows])
print("\nmean  llama w0=%.6f  ours w0=%.6f   mean |diff|=%.6f  max |diff|=%.6f"
      % (w0l.mean(), w0o.mean(), np.abs(w0o - w0l).mean(), np.abs(w0o - w0l).max()))
print("weight sum: mean=%.6f min=%.6f max=%.6f"
      % ((w0o + w1o).mean(), (w0o + w1o).min(), (w0o + w1o).max()))

# If only the SCALE is off, w0_ours/w1_ours = exp(s_ours*d)/exp(s_ours*d) and
# the implied scale can be recovered from the solved weights + llama's dots.
nek, kr = read_llama("k_attn")
K = kr.reshape(nek[2], nek[1], nek[0])
neq, qr = read_llama("q_attn")
Q = qr.reshape(neq[1], neq[0])
print("\nimplied scale from the solved weights (head 0):")
dots = np.array([float(Q[0] @ K[0, kv]) for kv in range(n_kv)])
for h in [0]:
    sol = np.array([w0o[h], w1o[h]])
    p = np.exp(np.log(np.maximum(sol, 1e-12)))
    # s = log(w0/w1) / (d0 - d1)
    if n_kv == 2 and abs(dots[0] - dots[1]) > 1e-6:
        s_ours = np.log(max(sol[0], 1e-12) / max(sol[1], 1e-12)) / (dots[0] - dots[1])
        s_llama = np.log(max(Soft[0, 0][0], 1e-12) / max(Soft[0, 1][0], 1e-12)) / (dots[0] - dots[1])
        print("  dots=%s" % np.round(dots, 6).tolist())
        print("  ours  implied scale = %.6f" % s_ours)
        print("  llama implied scale = %.6f" % s_llama)
