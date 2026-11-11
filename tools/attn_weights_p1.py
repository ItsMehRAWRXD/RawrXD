#!/usr/bin/env python3
"""Layer-0 position-1 attention WEIGHTS parity: our recorded softmax vs llama.cpp's
own kq_soft_max dump, per head and per attended slot. This separates "wrong
scores" from "wrong V" in the residual position-1 error.
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
Soft = sr.reshape(nes[2], nes[0], nes[1])   # [head][kv][1]
n_kv = STEP + 1

tags = ("_l%d_" % LAYER, "_l%02d_" % LAYER)
scores = ours = None
for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
    if ("_p%d_" % STEP) not in p:
        continue
    if not any(t in p for t in tags):
        continue
    b = open(p, "rb").read()
    cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
    arr = np.frombuffer(b[20 + 8 + 8:20 + 8 + 8 + cnt * 4],
                        dtype=np.float32).astype(np.float64)
    if "Attention_Scores" in p and scores is None:
        scores = (os.path.basename(p), arr)
    if "Attention_Weights" in p and ours is None:
        ours = (os.path.basename(p), arr)

print("llama softmax ne=%s -> %d heads x %d kv slots" % (list(nes), Soft.shape[0], Soft.shape[1]))
print("n_kv (valid slots) = %d" % n_kv)
if scores:
    print("our scores dump: %s -> %d floats (heads=%d x slots=%d)"
          % (scores[0], scores[1].size, 16, scores[1].size // 16))
if ours:
    print("our weights dump: %s -> %d floats\n" % (ours[0], ours[1].size))

if not scores:
    print("no recorded scores found")
    sys.exit(1)

S = scores[1]
n_heads = S.size // n_kv
print("\nour dump: %d heads x %d slots" % (n_heads, n_kv))

print("\nhead  llama[k0, k1]                 ours_scaled[k0, k1]              softmax(ours)       diff")
worst = 0.0
for h in range(min(n_heads, Soft.shape[0])):
    lv = [float(Soft[h, kv][0]) for kv in range(n_kv)]
    ov = [float(S[h * n_kv + kv]) for kv in range(n_kv)]
    e = np.exp(np.array(ov) - max(ov))
    w = e / e.sum()
    dv = max(abs(lv[k] - w[k]) for k in range(n_kv))
    worst = max(worst, dv)
    if h < 6 or dv > 0.001:
        print("h%-3d  [%.6f, %.6f]    [%11.6f, %11.6f]  [%.6f, %.6f]  %+.6f"
              % (h, lv[0], lv[1], ov[0], ov[1], w[0], w[1], w[0] - lv[0]))
print("\nmax weight diff = %.6f" % worst)
