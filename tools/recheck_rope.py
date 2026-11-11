#!/usr/bin/env python3
"""Re-verify the rope/kv cache path with a correct record parser."""
import os
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from diff_reader import read_record, take, take_shaped  # noqa: E402

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
POS = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current"


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


print("=== k_rope_raw: produced vs cache ===")
prod = take(ND, "MLA_k_rope_raw_l%d_p%d" % (LAYER, POS), LAYER, POS, 64)
cache_t = take_shaped(ND, "CacheKV_Prefix_l%d_p%d_k_rope_raw" % (LAYER, POS), LAYER, POS)
if cache_t:
    cache, shape = cache_t
    print("cache shape=%s size=%d" % (shape, cache.size))
    if prod is not None and cache.size >= 64 * (POS + 1):
        slot = cache[64 * POS:64 * (POS + 1)]
        print("produced[:6] :", np.round(prod[:6], 6).tolist())
        print("cache slot%d[:6]:" % POS, np.round(slot[:6], 6).tolist())
        print("slot%d vs produced: cos=%.8f max|d|=%.6f"
              % (POS, cos(slot, prod), float(np.abs(slot - prod).max())))

print("\n=== expanded KV vs llama (corrected parse) ===")
exp_t = take_shaped(ND, "MLA_expanded_l%d_p%d" % (LAYER, POS), LAYER, POS)
if exp_t:
    exp, shape = exp_t
    print("our expanded shape=%s size=%d" % (shape, exp.size))
    raw = open(os.path.join(D, "probe_step%02d_k_attn_l%02d.bin" % (POS, LAYER)), "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    K = np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64).reshape(ne[2], ne[1], ne[0])
    raww = open(os.path.join(D, "probe_step%02d_v_attn_l%02d.bin" % (POS, LAYER)), "rb").read()
    nev = struct.unpack("<4q", raww[4:36])
    V = np.frombuffer(raww[68:], dtype=np.float32).astype(np.float64).reshape(nev[2], nev[1], nev[0])
    if exp.size == 16 * 256:
        E = exp.reshape(16, 256)
        kn = [cos(E[h][:128], K[h][POS][:128]) for h in range(16)]
        vc = [cos(E[h][128:256], V[h][:, POS]) for h in range(16)]
        print("k_nope: min cos %.6f mean %.6f" % (min(kn), sum(kn) / 16))
        print("value : min cos %.6f mean %.6f" % (min(vc), sum(vc) / 16))

print("\n=== attention output parity (corrected parse) ===")
out = take(ND, "Attention_Output_l%d_p%d" % (LAYER, POS), LAYER, POS, 2048)
nes_t = take_shaped(ND, "Attention_Scores_l%d_p%d" % (LAYER, POS), LAYER, POS)
if out is not None:
    sr = open(os.path.join(D, "probe_step%02d_kq_soft_max_l%02d.bin" % (POS, LAYER)), "rb").read()
    nes = struct.unpack("<4q", sr[4:36])
    Soft = np.frombuffer(sr[68:], dtype=np.float32).astype(np.float64).reshape(nes[2], nes[0], nes[1])
    raww = open(os.path.join(D, "probe_step%02d_v_attn_l%02d.bin" % (POS, LAYER)), "rb").read()
    nev = struct.unpack("<4q", raww[4:36])
    V = np.frombuffer(raww[68:], dtype=np.float32).astype(np.float64).reshape(nev[2], nev[1], nev[0])
    ref = np.zeros(2048)
    for h in range(16):
        acc = np.zeros(128)
        for kv in range(POS + 1):
            acc += Soft[h][kv][0] * V[h][:, kv]
        ref[h * 128:(h + 1) * 128] = acc
    print("attention output cos=%.8f max|d|=%.8f"
          % (cos(out, ref), float(np.abs(out - ref).max())))
