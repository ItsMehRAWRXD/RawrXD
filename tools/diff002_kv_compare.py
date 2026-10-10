#!/usr/bin/env python3
"""REFERENCE_DIFFERENTIAL_002: compare llama.cpp cached K/V against the
reference-derived values and the native runtime cache, using the decoded
[head][slot][dim] layout established by diagonal matching.
"""
import os
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from decode_kv_layout import read_probe  # noqa: E402
from weight_parity_probe import GGUF, REF, dequant_q4_k, parse_gguf_tables, rd_ref  # noqa: E402
from mla_attention_probe import quant_q8k_512  # noqa: E402

HEADS = 16
NOPE = 128
ROPE = 64


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else \
        r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
    step = sys.argv[2] if len(sys.argv) > 2 else "01"

    kv, T, te = parse_gguf_tables(GGUF)
    ds = (te + 31) // 32 * 32
    rawf = open(GGUF, "rb").read()

    def deq(n):
        t = T[n]
        c = int(np.prod(t["dims"]))
        off = ds + t["offset"]
        if t["type"] == 12:
            w = dequant_q4_k(rawf[off:off + c // 256 * 144], c)
        else:
            w = np.frombuffer(rawf[off:off + c * 4], dtype=np.float32).astype(np.float64)[:c]
        return w.reshape(t["dims"][0], t["dims"][1], order="F")

    wkv_b = deq("blk.0.attn_kv_b.weight")

    nek, _, Krows = read_probe(os.path.join(d, "probe_step%s_k_attn_l00.bin" % step))
    nev, _, Vrows = read_probe(os.path.join(d, "probe_step%s_v_attn_l00.bin" % step))
    neq, _, Qrows = read_probe(os.path.join(d, "probe_step%s_q_attn_l00.bin" % step))

    # rows are head-major, slot-fastest: reshape [heads][slots][dim]
    kh = nek[2]
    kslots = nek[1]
    K = Krows.reshape(kh, kslots, nek[0])
    vh = nev[2]
    vslots = nev[1]
    V = Vrows.reshape(vh, vslots, nev[0])
    Q = Qrows.reshape(neq[2], neq[0])   # [heads][dim]

    n_kv = int(step) + 1
    lat = [rd_ref(os.path.join(REF, "ref_capture_v9",
                               "ref_l00_p%02d_kv_cmpr.bin" % p))["v"] for p in range(n_kv)]

    print("k_attn: %d heads x %d slots x %d dims (active n_kv=%d)" % (kh, kslots, nek[0], n_kv))
    print("v_attn: %d heads x %d slots x %d dims" % (vh, vslots, nev[0]))

    print("\n-- per-head/per-slot cosine: llama cache vs wk_b @ Q8(ref latent) --")
    print("%-5s %-8s %-10s %-10s" % ("head", "slot", "k_nope", "k_pe(rope)"))
    kpe_cos = []
    kn_cos = []
    v_cos = []
    for h in [0, 1, 2, 15]:
        for s in [0, 1, 2][:n_kv]:
            exp_kn = wkv_b[:, h * 256 + 0:h * 256 + NOPE].T @ quant_q8k_512(lat[s])
            lq = quant_q8k_512(lat[s])
            exp_v = wkv_b[:, h * 256 + NOPE:(h + 1) * 256].T @ lq
            got_kn = K[h, s, :NOPE]
            got_v = V[h, s, :NOPE]
            kn_cos.append(cos(got_kn, exp_kn))
            v_cos.append(cos(got_v, exp_v))
            print("h%-4d s%-7d %-10.6f  (%s v=%.6f)" %
                  (h, s, cos(got_kn, exp_kn), "v:", cos(got_v, exp_v)))

    print("\nk_nope cos: min=%.6f mean=%.6f" % (min(kn_cos), sum(kn_cos) / len(kn_cos)))
    print("V     cos: min=%.6f mean=%.6f" % (min(v_cos), sum(v_cos) / len(v_cos)))

    # score check: q . (k_nope + k_pe) using llama's own cached values
    print("\n-- scores from llama's cached K (head 0, position %d) --" % (n_kv - 1))
    mscale = (1 * (1 + 0.1 * np.log(40))) * (1 + 0.1 * 0.707 * np.log(40))
    scale = mscale * mscale / np.sqrt(192.0)
    scores = []
    for s in range(n_kv):
        k = K[0, s, :192]
        scores.append(float(Q[0] @ k) * scale)
    print("llama raw dots:", [round(x, 5) for x in scores])
    print("(native scores for comparison were ~[3.352, 4.621, -1.312] at pos 2)")


if __name__ == "__main__":
    main()
