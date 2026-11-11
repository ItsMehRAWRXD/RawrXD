#!/usr/bin/env python3
"""Where does our roped k_pe diverge: compare (a) our runtime's own roped k_pe
dump, and (b) our runtime's rope formula applied to our cached raw k_pe, against
llama.cpp's roped k_pe for the same layer/position."""
import glob
import math
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
POS = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current"

NOPE, ROPE = 128, 64
BASE, FS, CTXO, BETA_F, BETA_S = 10000.0, 0.025, 4096.0, 32.0, 1.0


def rec_at(label, layer, p):
    for path in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label not in path or ("_p%d_" % p) not in path:
            continue
        if ("_l%d_" % layer) not in path and ("_l%02d_" % layer) not in path:
            continue
        b = open(path, "rb").read()
        cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
        return np.frombuffer(b[20 + 8 + 8:20 + 8 + 8 + cnt * 4],
                            dtype=np.float32).astype(np.float64)
    return None


def read_llama(name, step, layer):
    raw = open(os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (step, name, layer)), "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    return ne, np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


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


def rope(v, pos):
    out = np.zeros_like(v)
    for i in range(0, ROPE, 2):
        th = alpha(i // 2, pos)
        c, s = math.cos(th), math.sin(th)
        x, y = v[i], v[i + 1]
        out[i] = x * c - y * s
        out[i + 1] = x * s + y * c
    return out


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


nk, kr = read_llama("k_attn", POS, LAYER)
K = kr.reshape(nk[2], nk[1], nk[0])    # [head][slot][192]
llama_pe = K[0][POS][128:192]

ours_roped = rec_at("MLA_k_rope_l%d_p%d" % (LAYER, POS), LAYER, POS)
ours_raw = rec_at("CacheKV_Prefix_l%d_p%d_k_rope_raw" % (LAYER, POS), LAYER, POS)

print("layer %d position %d" % (LAYER, POS))
print("our MLA_k_rope dump      :", None if ours_roped is None else ours_roped.size)
print("our cached k_rope_raw    :", None if ours_raw is None else ours_raw.size)
print("llama roped k_pe (h0)    : %d" % llama_pe.size)

if ours_roped is not None and ours_roped.size == 64:
    print("\n(a) our roped k_pe (dump)      vs llama  cos=%.8f max|d|=%.6f"
          % (cos(ours_roped, llama_pe), float(np.abs(ours_roped - llama_pe).max())))
if ours_raw is not None:
    mine = rope(ours_raw, POS)
    print("(b) our rope(raw, MGRope::Alpha) vs llama  cos=%.8f max|d|=%.6f"
          % (cos(mine, llama_pe), float(np.abs(mine - llama_pe).max())))
    print("\nfirst 6 raw  :", np.round(ours_raw[:6], 6).tolist())
    print("first 6 our rope:", np.round(mine[:6], 6).tolist())
    print("first 6 llama   :", np.round(llama_pe[:6], 6).tolist())

    # what angle would reproduce llama's k_pe from the same raw input?
    print("\nsolved phase per pair (ours vs llama):")
    for pair in range(4):
        i = pair * 2
        x, y = ours_raw[i], ours_raw[i + 1]
        print("  pair %d: raw=(%.6f,%.6f) llama=(%.6f,%.6f) ours=(%.6f,%.6f)"
              % (pair, x, y, llama_pe[i], llama_pe[i + 1], mine[i], mine[i + 1]))
        # angle that produced llama's output
        ang_ll = math.atan2(llama_pe[i + 1], llama_pe[i]) - math.atan2(y, x)
        ang_ou = alpha(pair, POS)
        print("        implied llama theta=%+.6f rad  MGRope::Alpha theta=%+.6f rad  Delta=%+.6f"
              % (ang_ll, ang_ou, ang_ll - ang_ou))
