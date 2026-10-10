#!/usr/bin/env python3
"""Clean comparison of the produced k_rope_raw against the cache contents for
both attended positions (the cache prefix dump holds Size() x 64 floats)."""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
POS = int(sys.argv[2]) if len(sys.argv) > 2 else 1
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current"
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"


def floats(path):
    b = open(path, "rb").read()
    return np.frombuffer(b[36:], dtype=np.float32).astype(np.float64)


def find(label, p):
    for path in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label in path and ("_p%d_" % p) in path and (
                ("_l%d_" % LAYER) in path or ("_l%02d_" % LAYER) in path):
            return path
    return None


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


cache_p1 = floats(find("CacheKV_Prefix_l%d_p%d_k_rope_raw" % (LAYER, 1), 1))
cache_p0 = floats(find("CacheKV_Prefix_l%d_p%d_k_rope_raw" % (LAYER, 0), 0))
prod_p1 = floats(find("MLA_k_rope_raw_l%d_p1" % LAYER, 1))

print("cache after p0: %d floats (expect 64)" % cache_p0.size)
print("cache after p1: %d floats (expect 128)" % cache_p1.size)
print("produced at p1 : %d floats (expect 64)" % prod_p1.size)

if cache_p1.size >= 128:
    print("\ncache[0:64]  (position 0 raw):", np.round(cache_p1[:6], 6).tolist())
    print("cache[64:128] (position 1 raw):", np.round(cache_p1[64:70], 6).tolist())
    print("produced p1                    :", np.round(prod_p1[:6], 6).tolist())
    print("\ncache slot1 vs produced p1: cos=%.8f max|d|=%.6f"
          % (cos(cache_p1[64:128], prod_p1), float(np.abs(cache_p1[64:128] - prod_p1).max())))

if cache_p0.size >= 64:
    print("cache p0[0:64]                  :", np.round(cache_p0[:6], 6).tolist())

# llama's roped k_pe for slot 0 and 1
for step in range(POS + 1):
    raw = open(os.path.join(D, "probe_step%02d_k_attn_l%02d.bin" % (step, LAYER)), "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    K = np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64).reshape(ne[2], ne[1], ne[0])
    print("\nllama k_pe slot %d (h0)[:6]:" % step, np.round(K[0][step][128:134], 6).tolist())
