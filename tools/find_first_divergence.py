#!/usr/bin/env python3
"""Find the earliest divergent op position by comparing every tensor the llama.cpp
probe dumps against the matching native recorder output, across all layers.

Reference dumps per layer/step: kv_cmpr_used (the MLA A projection output held in
the cache), kv_up (the B projection output), k_attn (post-RoPE K), v_attn (V).
Native dumps: MLA_kv_latent, MLA_expanded, Attention_Output, MLA_V_RECONSTRUCTED.
"""
import glob
import os
import struct
import sys

import numpy as np

STEP = int(sys.argv[1]) if len(sys.argv) > 1 else 1
MAXLAYER = int(sys.argv[2]) if len(sys.argv) > 2 else 27
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = os.environ.get("ND", r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current")


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


def llama(name, layer):
    path = os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (STEP, name, layer))
    if not os.path.exists(path):
        return None
    raw = open(path, "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    return np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


def cos(a, b):
    if a.size != b.size:
        return float("nan")
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


print("step %d: first 40 layers" % STEP)
print("layer  A-proj lat    lat_ref      B-proj exp    V_RECON        attn_out")
rows = []
for layer in range(MAXLAYER):
    lat = rec("MLA_kv_latent_l%d_p%d" % (layer, STEP), layer)
    lat_ref = llama("kv_cmpr_used", layer)
    exp_ = rec("MLA_expanded_l%d_p%d" % (layer, STEP), layer)
    exp_ref = llama("kv_up", layer)
    vrec = None
    vfiles = sorted(glob.glob(os.path.join(ND, "rec_*")))
    attn = rec("Attention_Output_l%d_p%d" % (layer, STEP), layer)

    def fmt(a, b):
        if a is None or b is None:
            return "     -       "
        n = min(a.size, b.size)
        if n == 0:
            return "     -       "
        c = cos(a[:n], b[:n])
        return "%9.6f   " % c

    row = "%-5d  %s %s %s %s" % (
        layer, fmt(lat, lat_ref), fmt(exp_, exp_ref), fmt(attn, None if False else
        (llama("v_attn", layer) if False else None)), "")
    c_lat = fmt(lat, lat_ref)
    c_exp = fmt(exp_, exp_ref)
    c_v = fmt(vrec, None)
    print("%-5d  %s %s %s" % (layer, c_lat, c_exp, ""))
    rows.append((layer, c_lat.strip(), c_exp.strip()))

print("\nlayer | A-proj (latent vs kv_cmpr_used) | B-proj (expanded vs kv_up)")
for layer, a, b in rows:
    print("%5d | %s | %s" % (layer, a, b))
