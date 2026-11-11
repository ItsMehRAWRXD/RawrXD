#!/usr/bin/env python3
"""REFERENCE_DIFFERENTIAL_002 step 2: with graph outputs marked, verify the
attention score path end to end against llama.cpp's own dumped tensors.
"""
import math
import os
import struct
import sys

import numpy as np

D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1b"

NOPE, ROPE = 128, 64
BASE, FS, CTXO, BETA_F, BETA_S = 10000.0, 0.025, 4096.0, 32.0, 1.0


def rd(name, step, layer="l00"):
    path = os.path.join(D, "probe_step%02d_%s_%s.bin" % (step, name, layer))
    raw = open(path, "rb").read()
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


def native_op3(pos):
    for f in sorted(os.listdir(ND)):
        if f.startswith("rec_") and "op3_" in f:
            b = open(os.path.join(ND, f), "rb").read()
            if struct.unpack_from("<I", b, 4)[0] != 0:
                continue
            if struct.unpack_from("<Q", b, 8)[0] != pos:
                continue
            cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
            return np.frombuffer(b[20 + 8 + 8:20 + 8 + 8 + cnt * 4],
                                 dtype=np.float32).astype(np.float64)
    return None


def main():
    step = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    mscale = (1 * (1 + 0.1 * math.log(40))) * (1 + 0.1 * 0.707 * math.log(40))
    scale = mscale * mscale / math.sqrt(192.0)
    n_kv = step + 1

    nek, kr = rd("k_attn", step)
    neq, qr = rd("q_attn", step)
    nes, sr = rd("kq_soft_max", step)
    nep, qpr = rd("q_proj", step)

    K = kr.reshape(nek[2], nek[1], nek[0])     # [head][slot][dim]
    Q = qr.reshape(16, 192)                    # [head][dim]
    Soft = sr.reshape(16, 256)
    Qproj = qpr.reshape(-1, nep[0])

    print("=== step %d (position %d), layer 0 ===" % (step, step))
    print("dumped q_proj vs native q matvec: cos=%.9f maxdiff=%.3g"
          % (cos(Qproj[0], native_op3(step)[:192]),
             float(np.abs(Qproj[0] - native_op3(step)[:192]).max())))

    # reference score check from the dumps themselves
    for h in [0]:
        dots = [float(Q[h] @ K[h, s, :192]) for s in range(n_kv)]
        e = np.exp(np.array(dots) * scale - max(np.array(dots) * scale))
        w = e / e.sum()
        print("self-check h%d: computed %s vs dumped %s"
              % (h, np.round(w, 6).tolist(), np.round(Soft[h, :n_kv], 6).tolist()))

    # rope check: llama's dumped q_pe vs our rope of the q projection
    nat = native_op3(step).reshape(16, 192)
    q_pe_ours = rope(nat[0, NOPE:192], step)
    print("rope check h0: llama q_pe vs our rope(q_proj pe): cos=%.8f"
          % cos(Q[0, NOPE:192], q_pe_ours))
    print("  llАма q_pe[:4]:", np.round(Q[0, 128 + 0:128 + 4], 5).tolist())
    print("  ours  q_pe[:4]:", np.round(q_pe_ours[:4], 5).tolist())
    print("  raw   pe[:4]  :", np.round(nat[0, NOPE:NOPE + 4], 5).tolist())

    # k_pe rope check: llama's cached k_pe vs our rope of k_pe raw
    neku, kur = rd("kv_cmpr_used", step)
    kv_cmpr = kur.reshape(-1, neku[0])[:512] if kur.size >= 512 else None
    # our runtime's roped k_pe comes from alpha() on the raw rope part of the latent
    print("k_pe(l0,s0) llАma[:4]:", np.round(K[0, 0, 128:132], 5).tolist())

    # full score comparison: native vs reference
    print("\nscore comparison (h0, unscaled q.k):")
    for s in range(n_kv):
        k = K[0, s, :192]
        ours = float(nat[0, :NOPE] @ k[:NOPE]) + float(q_pe_ours @ k[NOPE:])
        print("  slot %d: llama dot=%9.4f   ours dot=%9.4f   diff=%+9.4f"
              % (s, float(Q[0] @ k), ours, ours - float(Q[0] @ k)))


if __name__ == "__main__":
    main()
