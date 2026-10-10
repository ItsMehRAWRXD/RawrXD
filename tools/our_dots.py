#!/usr/bin/env python3
"""Reconstruct OUR attention dots at (layer, step) from our own dumps and compare
with llama.cpp's kq path. Our runtime stores k_rope_raw per position and applies
MGRope::Alpha's YaRN angle at attention time, so this recomputes exactly what the
runtime used: score = scale * (q_nope.k_nope + q_pe.k_pe)."""
import glob
import math
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current"

NOPE, ROPE = 128, 64
BASE, FS, CTXO, BETA_F, BETA_S = 10000.0, 0.025, 4096.0, 32.0, 1.0


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


def corr(beta):
    return ROPE * math.log(CTXO / (beta * 2 * math.pi)) / (2 * math.log(BASE))


LOW = max(0, math.floor(corr(BETA_F)))
HIGH = min(ROPE - 1, math.ceil(corr(BETA_S)))


def alpha(k, pos):
    tex = pos * BASE ** (-2.0 * k / ROPE)
    tin = FS * tex
    y = (k - LOW) / max(0.001, HIGH - LOW)
    ramp = 1 - min(1, max(0, y))
    return tin * (1.0 - ramp) + tex * ramp


def rec_at(label, layer, rec_pos):
    for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label not in p or ("_p%d_" % rec_pos) not in p:
            continue
        if ("_l%d_" % layer) not in p and ("_l%02d_" % layer) not in p:
            continue
        b = open(p, "rb").read()
        cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
        return np.frombuffer(b[20 + 8 + 8:20 + 8 + 8 + cnt * 4],
                            dtype=np.float32).astype(np.float64)
    return None


def rope(v, pos):
    out = np.zeros_like(v)
    for i in range(0, ROPE, 2):
        th = alpha(i // 2, pos)
        c, s = math.cos(th), math.sin(th)
        x, y = v[i], v[i + 1]
        out[i] = x * c - y * s
        out[i + 1] = x * s + y * c
    return out


nq, qr = read_llama("q_attn")
Q = qr.reshape(-1, nq[0])                      # [head][192]
nk, kr = read_llama("k_attn")
K_llama = kr.reshape(nk[2], nk[1], nk[0])      # [head][slot][192]

q = rec_at("Attention_Q_RoPE", LAYER, STEP)
exp = rec_at("MLA_expanded", LAYER, STEP)
rope_raw = {slot: rec_at("CacheKV_Prefix_l%d_p%d_k_rope_raw" % (LAYER, slot),
                         LAYER, slot) for slot in range(STEP + 1)}
n_kv = STEP + 1

Qours = q.reshape(-1, 192)
E = exp.reshape(16, 256)
SCALE = 0.114721403

print("head   slot   dot(ours)      dot(llama)     diff        |  k_pe dot(ours vs llama)")
for h in [0, 1, 2, 5]:
    for slot in range(n_kv):
        kn = E[h][:128]
        pe = rope(rope_raw[slot], slot) if rope_raw[slot] is not None else None
        ours_nope = float(Qours[h][:128] @ kn)
        ours_pe = float(Qours[h][128:192] @ pe) if pe is not None else float("nan")
        llama_pe = float(Q[h][128:192] @ K_llama[h][slot][128:192])
        print("h%-3d   s%-3d  %12.6f %12.6f %+11.6f   |  pe %10.6f vs %10.6f"
              % (h, slot, ours_nope + ours_pe, float(Q[h] @ K_llama[h][slot]),
                 ours_nope + ours_pe - float(Q[h] @ K_llama[h][slot]),
                 ours_pe, llama_pe))
