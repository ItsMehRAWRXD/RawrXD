#!/usr/bin/env python3
"""Compare our runtime's expanded MLA K/V against llama.cpp's k_attn/v_attn for
the current position (slot 1). Our MLA_expanded holds [k_nope(128) | v(128)] per
head; llama's k_attn holds [k_nope(128) | k_pe(64) with RoPE] and v_attn holds V.
The k_nope halves are directly comparable (RoPE does not touch them)."""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current"


def read_llama(name):
    raw = open(os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (STEP, name, LAYER)), "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    return ne, np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


def rec(label):
    for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label not in p or ("_p%d_" % STEP) not in p:
            continue
        if ("_l%d_" % LAYER) not in p and ("_l%02d_" % LAYER) not in p:
            continue
        b = open(p, "rb").read()
        cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
        return np.frombuffer(b[20 + 8 + 8:20 + 8 + 8 + cnt * 4],
                            dtype=np.float32).astype(np.float64)
    return None


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


nec, kr = read_llama("k_attn")
nev, vr = read_llama("v_attn")
K = kr.reshape(nec[2], nec[1], nec[0])   # [head][slot][192]
V = vr.reshape(nev[2], nev[1], nev[0])   # [head][dim][slot]

exp = rec("MLA_expanded")
print("our MLA_expanded size=%s (expect %d)" % (None if exp is None else exp.size, 16 * 256))
if exp is None:
    sys.exit(1)
E = exp.reshape(16, 256)
print("\nhead   k_nope cos(ours,llama)   v cos(ours,llama)   |k_nope diff|   |v diff|")
kn, vc, kd, vd = [], [], [], []
for h in range(16):
    k_ours = E[h][:128]
    v_ours = E[h][128:256]
    k_ref = K[h][STEP][:128]
    v_ref = V[h][:, STEP]
    kn.append(cos(k_ours, k_ref)); vc.append(cos(v_ours, v_ref))
    kd.append(float(np.abs(k_ours - k_ref).max())); vd.append(float(np.abs(v_ours - v_ref).max()))
    print("h%-3d   %16.6f %18.6f %14.6f %11.6f"
          % (h, kn[-1], vc[-1], kd[-1], vd[-1]))
print("\nk_nope: min cos %.6f mean cos %.6f max|d| %.6f"
      % (min(kn), sum(kn) / 16, max(kd)))
print("value : min cos %.6f mean cos %.6f max|d| %.6f"
      % (min(vc), sum(vc) / 16, max(vd)))

# The rope half of our expanded tensor versus llama's raw rope part of the
# latent is only comparable pre-RoPE; llama's k_attn has it roped.
print("\nfirst 6 k_nope ours:", np.round(E[0][:6], 6).tolist())
print("first 6 k_nope ref :", np.round(K[0][STEP][:6], 6).tolist())
