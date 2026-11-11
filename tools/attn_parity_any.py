#!/usr/bin/env python3
"""Attention-output parity at an arbitrary (layer, step): reconstruct llama.cpp's
attention output from its OWN kq_soft_max and v_attn dumps and compare with the
runtime's recorded Attention_Output. This is the end-to-end attention gate (it
folds scores, softmax, V and the cache read together), so a clean result here
means the score scale and the cached read path are both right."""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 2
ND = sys.argv[3] if len(sys.argv) > 3 else \
    r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos2_current"
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"


def read_llama(name):
    raw = open(os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (STEP, name, LAYER)), "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    return ne, np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


def rec(label):
    tags = ("_l%d_" % LAYER, "_l%02d_" % LAYER)
    for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label not in p or ("_p%d_" % STEP) not in p:
            continue
        if not any(t in p for t in tags):
            continue
        b = open(p, "rb").read()
        ndim = struct.unpack_from("<I", b, 16)[0]
        start = 20 + 8 * ndim + 8
        return np.frombuffer(b[start:], dtype=np.float32).astype(np.float64)
    return None


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


nes, sr = read_llama("kq_soft_max")
nev, vr = read_llama("v_attn")
Soft = sr.reshape(nes[2], nes[0], nes[1])
V = vr.reshape(nev[2], nev[1], nev[0])
n_kv = STEP + 1

out = rec("Attention_Output")
if out is None:
    print("no attention output recorded for layer %d step %d" % (LAYER, STEP))
    sys.exit(1)
ref = np.zeros(2048)
for h in range(16):
    acc = np.zeros(128)
    for kv in range(n_kv):
        acc += Soft[h][kv][0] * V[h][:, kv]
    ref[h * 128:(h + 1) * 128] = acc

print("layer %d step %d (n_kv=%d)" % (LAYER, STEP, n_kv))
print("attention output cos(ours,llama) = %.9f  max|d| = %.8f"
      % (cos(out, ref), float(np.abs(out - ref).max())))
d = np.abs(out - ref)
print("rms|d| = %.8f  mean|d| = %.8f" % (float(np.sqrt((d * d).mean())), float(d.mean())))

# Implied scale check: solve each head's weights from our output and llama's V
E = rec("MLA_expanded")
q = rec("Attention_Q_RoPE")
if E is not None and q is not None and E.size == 4096:
    Eq = q.reshape(-1, 192)
    print("\nimplied scale per head (from the solved weights):")
    for h in range(4):
        A = np.stack([V[h][:, kv] for kv in range(n_kv)], axis=1)
        sol, *_ = np.linalg.lstsq(A, out[h * 128:(h + 1) *128], rcond=None)
        p = np.maximum(sol, 1e-12)
        lnr = np.log(p)
        dots = [float(Eq[h][:128] @ E.reshape(16, 256)[h][:128]) for _ in [0]]
        # dot contribution from rope part is not recoverable here; report the
        # weight ratio against llama's own weights instead
        lv = [float(Soft[h][kv][0]) for kv in range(n_kv)]
        print("  h%-2d llama w=%s  ours w=%s"
              % (h, np.round(lv, 6).tolist(), np.round(sol, 6).tolist()))
