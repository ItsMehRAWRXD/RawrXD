#!/usr/bin/env python3
"""Native vs llama for the two MLA projections and the attention output, with
max/rms deltas, for one layer/step."""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = os.environ.get(
    "ND", r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current")


def read_record(path):
    b = open(path, "rb").read()
    _, _, _, ndim = struct.unpack_from("<IIQI", b, 0)
    off = 20 + 8 * ndim + 8
    return np.frombuffer(b[off:], dtype=np.float32).astype(np.float64)


def rec(label, layer):
    tags = ("_l%d_" % layer, "_l%02d_" % layer)
    for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label not in p or ("_p%d_" % STEP) not in p:
            continue
        if not any(t in p for t in tags):
            continue
        return read_record(p)
    return None


def llama(name, layer, step):
    path = os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (step, name, layer))
    if not os.path.exists(path):
        return None
    raw = open(path, "rb").read()
    return np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


def stats(a, b):
    n = min(a.size, b.size)
    a, b = a[:n], b[:n]
    d = np.abs(a - b)
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    cos = float(a @ b / (na * nb)) if na and nb else float("nan")
    return cos, float(d.max()), float(np.sqrt((d * d).mean()))


print("layer %d step %d" % (LAYER, STEP))
for label, ours, ref in (
    ("A-proj latent", rec("MLA_kv_latent_l%d_p%d" % (LAYER, STEP), LAYER),
     llama("kv_cmpr_used", LAYER, STEP)),
    ("B-proj expanded", rec("MLA_expanded_l%d_p%d" % (LAYER, STEP), LAYER),
     llama("kv_up", LAYER, STEP)),
    ("attention out", rec("Attention_Output_l%d_p%d" % (LAYER, STEP), LAYER),
     None),
):
    if ours is None or ref is None:
        print("  %-16s unavailable" % label)
        continue
    c, mx, rms = stats(ours, ref)
    print("  %-16s cos=%.10f max|d|=%.8f rms=%.8f" % (label, c, mx, rms))
