#!/usr/bin/env python3
"""Compare the k_rope_raw recorded when it was produced (op0_MLA_k_rope_raw)
against what landed in the cache (op2_MLA_CacheKV_Prefix..._k_rope_raw), and
against the write-time roped k_pe (op0_MLA_k_rope). If the cache holds different
bytes than the produced raw rope part, the attention read path is operating on
the wrong data."""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
POS = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current"


def rec_at(label, layer, p, prefer=None):
    hits = []
    for path in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label not in path or ("_p%d_" % p) not in path:
            continue
        if ("_l%d_" % layer) not in path and ("_l%02d_" % layer) not in path:
            continue
        b = open(path, "rb").read()
        cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
        hits.append((os.path.basename(path),
                    np.frombuffer(b[20 + 8 + 8:20 + 8 + 8 + cnt * 4],
                                 dtype=np.float32).astype(np.float64)))
    return hits


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


print("layer %d position %d" % (LAYER, POS))
groups = {
    "MLA_k_rope_raw (produced)": rec_at("MLA_k_rope_raw_l%d_p%d" % (LAYER, POS), LAYER, POS),
    "CacheKV k_rope_raw (cached)": rec_at("CacheKV_Prefix_l%d_p%d_k_rope_raw" % (LAYER, POS), LAYER, POS),
    "MLA_k_rope (roped at write)": rec_at("MLA_k_rope_l%d_p%d" % (LAYER, POS), LAYER, POS),
    "MLA_kv_latent (produced)": rec_at("MLA_kv_latent_l%d_p%d" % (LAYER, POS), LAYER, POS),
    "CacheKV kv_latent (cached)": rec_at("CacheKV_Prefix_l%d_p%d_kv_latent" % (LAYER, POS), LAYER, POS),
}
for name, hits in groups.items():
    print("  %-32s %d file(s), size=%s" % (name, len(hits),
          hits[0][1].size if hits else None))

def one(name):
    h = groups[name]
    return h[0][1] if h else None

raw_prod = one("MLA_k_rope_raw (produced)")
raw_cache = one("CacheKV k_rope_raw (cached)")
roped = one("MLA_k_rope (roped at write)")

if raw_prod is not None and raw_cache is not None and raw_prod.size == raw_cache.size:
    print("\nproduced vs cached k_rope_raw: cos=%.8f max|d|=%.6f"
          % (cos(raw_prod, raw_cache), float(np.abs(raw_prod - raw_cache).max())))
    print("  produced[:8]:", np.round(raw_prod[:8], 6).tolist())
    print("  cached  [:8]:", np.round(raw_cache[:8], 6).tolist())

if roped is not None:
    print("\nroped-at-write[:8]:", np.round(roped[:8], 6).tolist())
