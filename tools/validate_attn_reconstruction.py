#!/usr/bin/env python3
"""Validate the llama.cpp attention-output reconstruction (softmax x V) against
llama.cpp's own kqv dump, at every step, for a set of layers. If the
reconstruction matches kqv, the softmax/V layout assumptions are right and any
remaining difference against our runtime is real.
"""
import os
import struct
import sys

import numpy as np

D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
LAYERS = [int(x) for x in sys.argv[1].split(",")] if len(sys.argv) > 1 else [0, 1, 2]
MAXSTEP = int(sys.argv[2]) if len(sys.argv) > 2 else 3


def read(name, step, layer):
    p = os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (step, name, layer))
    if not os.path.exists(p):
        return None, None
    raw = open(p, "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    return ne, np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


def cos(a, b):
    if a.size != b.size:
        return float("nan")
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


for layer in LAYERS:
    for step in range(MAXSTEP):
        nes, sr = read("kq_soft_max", step, layer)
        nev, vr = read("v_attn", step, layer)
        nek, kr = read("kqv", step, layer)
        if sr is None or vr is None or kr is None:
            continue
        Soft = sr.reshape(nes[2], nes[0], nes[1])
        V = vr.reshape(nev[2], nev[1], nev[0])
        n_kv = step + 1
        out = np.zeros(V.shape[1])
        for h in range(Soft.shape[0]):
            acc = np.zeros(V.shape[1])
            for kv in range(n_kv):
                acc += Soft[h, kv][0] * V[h, :, kv]
            out = np.concatenate([out, acc]) if h else acc
        # kqv is 2048 floats for a 1-token step
        print("layer %2d step %d: reconstruction vs llama kqv  cos=%.9f  max|d|=%.8f"
              % (layer, step, cos(out, kr), float(np.abs(out - kr).max())))
