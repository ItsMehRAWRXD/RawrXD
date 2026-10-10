#!/usr/bin/env python3
"""Layer-0 position-1 attention output parity.

Reconstructs llama.cpp's attention output from its OWN dumps (kq_soft_max and
v_attn) and compares it with the runtime's recorded Attention_Output. This is
the end-to-end attention gate for the cached-position path: scores x V summed
over every attended slot, per head, then concatenated to the 2048-dim head
output.
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
    path = os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (STEP, name, LAYER))
    raw = open(path, "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    return ne, np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


def rec_first(pattern):
    tags = ("_l%d_" % LAYER, "_l%02d_" % LAYER)
    pos_tag = "_p%d_" % STEP
    for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if pattern not in p or pos_tag not in p:
            continue
        if not any(t in p for t in tags):
            continue
        b = open(p, "rb").read()
        cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
        return np.frombuffer(b[20 + 8 + 8:20 + 8 + 8 + cnt * 4],
                             dtype=np.float32).astype(np.float64)
    return None


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


nes, sr = read_llama("kq_soft_max")
nev, vr = read_llama("v_attn")
print("kq_soft_max ne=%s size=%d ; v_attn ne=%s size=%d"
      % (list(nes), sr.size, list(nev), vr.size))
# ne=[256, 16, 1] -> [head][kv slot] with 256 slots (n_kv=n_ctx)
if sr.size == 256 * nes[2] * nes[3] and nes[2] > 1:
    Soft = sr.reshape(nes[2], nes[0], nes[1])   # [head][kv][?]
    print("softmax reshaped as [%d][%d][%d]" % (nes[2], nes[0], nes[1]))
else:
    Soft = sr.reshape(-1)
    print("softmax flattened size=%d" % Soft.size)
V = vr.reshape(nev[2], nev[1], nev[0])      # [head][dim][slot]
n_kv = STEP + 1

# llama reference: sum over slots of softmax[h, kv] * V[h, :, kv]
ref_out = np.zeros((Soft.shape[0], V.shape[1]))
for h in range(Soft.shape[0]):
    acc = np.zeros(V.shape[1])
    for kv in range(n_kv):
        acc += Soft[h, kv] * V[h, :, kv]
    ref_out[h] = acc

ours = rec_first("Attention_Output")
print("layer %d step %d: our Attention_Output size=%d (expected %d)"
      % (LAYER, STEP, None if ours is None else ours.size, 16 * V.shape[1]))
if ours is None:
    print("no recorded attention output found")
    sys.exit(1)

flat = ref_out.reshape(-1)
print("ref reconstruction size=%d" % flat.size)
# our dump is [head][dim] flattened head-major
c = cos(ours[:flat.size], flat)
print("attention output cos(ours,llama) = %.9f" % c)
d = np.abs(ours[:flat.size] - flat)
print("max|d|=%.8f rms=%.8f mean|d|=%.8f"
      % (d.max(), float(np.sqrt((d ** 2).mean())), float(d.mean())))
print("\nfirst 8 ours:", np.round(ours[:8], 6).tolist())
print("first 8 ref :", np.round(flat[:8], 6).tolist())
