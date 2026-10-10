#!/usr/bin/env python3
"""REFERENCE_DIFFERENTIAL_002: score-path isolation at layer 0.

Uses llama.cpp's own cached K (decoded as [head][slot][dim]) and the
authoritative softmax weights (kq_soft_max) to determine what the
reference score difference is, then checks which input the native runtime
must differ on.
"""
import os
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from decode_kv_layout import read_probe  # noqa: E402
from weight_parity_probe import GGUF, REF, dequant_q4_k, parse_gguf_tables, rd_ref  # noqa: E402
from mla_attention_probe import quant_q8k_512  # noqa: E402
import importlib.util

spec = importlib.util.spec_from_file_location("mv", os.path.join(os.path.dirname(__file__), "mla_variants.py"))
mv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mv)

NOPE, ROPE = 128, 64


def rope(v, pos):
    out = np.zeros_like(v)
    for i in range(0, ROPE, 2):
        a = mv.alpha(pos, i // 2)
        c, s = np.cos(a), np.sin(a)
        x, y = v[i], v[i + 1]
        out[i] = x * c - y * s
        out[i + 1] = x * s + y * c
    return out


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


def native_op3(nd, layer, pos, op):
    for f in sorted(os.listdir(nd)):
        want = "op%d_" % op
        if f.startswith("rec_") and want in f:
            b = open(os.path.join(nd, f), "rb").read()
            if struct.unpack_from("<I", b, 4)[0] != layer:
                continue
            if struct.unpack_from("<Q", b, 8)[0] != pos:
                continue
            cnt = struct.unpack_from("<Q", b, 20 + 8 * 1)[0]
            return np.frombuffer(b[20 + 8 * 1 + 8:20 + 8 * 1 + 8 + cnt * 4],
                                 dtype=np.float32).astype(np.float64)
    return None


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else \
        r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
    step = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    nd = sys.argv[3] if len(sys.argv) > 3 else \
        r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1b"

    nek, _, Kr = read_probe(os.path.join(d, "probe_step%02d_k_attn_l00.bin" % step))
    nes, _, Sr = read_probe(os.path.join(d, "probe_step%02d_kq_soft_max_l00.bin" % step))
    K = Kr.reshape(nek[2], nek[1], nek[0])       # [head][slot][dim]
    Soft = Sr.reshape(16, 256)                   # [head][kv]
    n_kv = step + 1

    # native q proj (pre-rope) at this position
    qnat = native_op3(nd, 0, step, 3)
    if qnat is None:
        print("native op3 not found for pos", step)
        return
    mscale = (1 * (1 + 0.1 * np.log(40))) * (1 + 0.1 * 0.707 * np.log(40))
    scale = mscale * mscale / np.sqrt(192.0)

    h = 0
    print("position %d, layer 0, head %d   (kq_scale=%.6f)" % (step, h, scale))
    print("llama softmax      :", np.round(Soft[h, :n_kv], 5).tolist())

    q_pe_ours = rope(qnat[h * 192 + NOPE:h * 192 + 192], step)
    print("our q_nope[:4]     :", np.round(qnat[h * 192:h * 192 + 4], 5).tolist())
    parts_ours, parts_llama = [], []
    for s in range(n_kv):
        k = K[h, s, :192]
        ours = float(qnat[h * 192:h * 192 + NOPE] @ k[:NOPE]) + float(q_pe_ours @ k[NOPE:])
        parts_ours.append(ours)
    d_ours = parts_ours[0] - parts_ours[-1]
    print("our raw dots       :", [round(x, 5) for x in parts_ours])
    print("our dot difference : %+.5f  -> softmax %s" %
          (d_ours, np.round(np.exp(np.array(parts_ours) * scale - max(np.array(parts_ours) * scale)) /
                            sum(np.exp(np.array(parts_ours) * scale - max(np.array(parts_ours) * scale))), 5).tolist()))
    # llama implied score difference from the softmax weights
    w = Soft[h, :n_kv]
    d_llama = np.log(w[0] / w[-1])
    print("llama dot diff (implied by softmax): %+.5f" % d_llama)

    # Which part differs? Compare q_nope . k_nope using llama's cached K vs our q
    print("\nper-slot decomposition with our q:")
    for s in range(n_kv):
        k = K[h, s, :192]
        pe = float(q_pe_ours @ k[NOPE:])
        nope = float(qnat[h * 192:h * 192 + NOPE] @ k[:NOPE])
        print("  slot %d: nope=%.5f pe=%.5f total=%.5f" % (s, nope, pe, nope + pe))

    # same but with the reference q dump (pre-rope) roped by our alpha
    qref = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_q.bin" % step))["v"]
    q_pe_ref = rope(qref[h * 192 + NOPE:h * 192 + 192], step)
    print("\nref q dump vs native q: nope cos=%.8f pe(pre-rope) cos=%.8f" %
          (cos(qref[h * 192:h * 192 + NOPE], qnat[h * 192:h * 192 + NOPE]),
           cos(qref[h * 192 + NOPE:h * 192 + 192], qnat[h * 192 + NOPE:h * 192 + 192])))

    # k_pe: llama's cached (roped) vs the reference dump
    kpe_ref = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_k_pe.bin" % step))["v"]
    print("llama cached k_pe vs ref k_pe dump: cos=%.8f" %
          cos(K[h, step, NOPE:], kpe_ref))


if __name__ == "__main__":
    main()
