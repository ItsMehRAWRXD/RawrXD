#!/usr/bin/env python3
"""Decide llama.cpp MLA attention numerics (corrected per-head rope).

Variants vs llama.cpp reference attn_out at layer 0, position 2:
  (a) exact q_nope x (wk^T @ Q8(latent))    - our current native
  (b) Q8(q_nope)   x (wk^T @ latent)       - llama absorbed, quantized q_nope
  (c) exact q_nope x (wk^T @ latent)       - absorbed, exact q_nope
  (d) Q8(q_nope)   x (wk^T @ Q8(latent))
"""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from mla_attention_probe import POS, quant_q8k_128, quant_q8k_512  # noqa: E402
from weight_parity_probe import GGUF, REF, dequant_q4_k, parse_gguf_tables, rd_ref  # noqa: E402


def alpha(position, k):
    tex = position * (10000.0 ** (-2.0 * k / 64))
    tin = 0.025 * tex
    cf = 64 * np.log(4096.0 / (32.0 * 2 * np.pi)) / (2 * np.log(10000.0))
    cs = 64 * np.log(4096.0 / (1.0 * 2 * np.pi)) / (2 * np.log(10000.0))
    low, high = np.floor(cf), np.ceil(cs)
    y = (k - low) / max(0.001, high - low)
    ramp = 1.0 if y <= 0 else (0.0 if y >= 1 else 1.0 - y)
    return tin * (1 - ramp) + tex * ramp


def main():
    kv, T, te = parse_gguf_tables(GGUF)
    ds = (te + 31) // 32 * 32
    raw = open(GGUF, "rb").read()

    def deq(n):
        t = T[n]
        c = int(np.prod(t["dims"]))
        off = ds + t["offset"]
        if t["type"] == 12:
            w = dequant_q4_k(raw[off:off + c // 256 * 144], c)
        else:
            w = np.frombuffer(raw[off:off + c * 4], dtype=np.float32).astype(np.float64)[:c]
        return w.reshape(t["dims"][0], t["dims"][1], order="F")

    wkv_b = deq("blk.0.attn_kv_b.weight")
    wo = deq("blk.0.attn_output.weight")
    lat = [rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_kv_cmpr.bin" % p))["v"]
           for p in range(POS + 1)]
    kpes = [rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_k_pe.bin" % p))["v"]
            for p in range(POS + 1)]
    q = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_q.bin" % POS))["v"]
    ref = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_attn_out.bin" % POS))["v"]

    mscale = (1 * (1 + 0.1 * np.log(40))) * (1 + 0.1 * 0.707 * np.log(40))
    scale = mscale * mscale / np.sqrt(192.0)

    def run(q8q, q8l, v8):
        O = np.zeros(2048)
        for h in range(16):
            qn = q[h * 192:h * 192 + 128]
            if q8q:
                qn = quant_q8k_128(qn)
            Vm = wkv_b[:, h * 256 + 128:(h + 1) * 256]
            Km = wkv_b[:, h * 256:h * 256 + 128]
            q_pe = np.zeros(64)
            for i in range(0, 64, 2):
                a = alpha(POS, i // 2)
                c, s = np.cos(a), np.sin(a)
                x, y = q[h * 192 + 128 + i], q[h * 192 + 128 + i + 1]
                q_pe[i] = x * c - y * s
                q_pe[i + 1] = x * s + y * c
            scores = []
            for p in range(POS + 1):
                latl = quant_q8k_512(lat[p]) if q8l else lat[p]
                kn = Km.T @ latl
                scores.append((np.dot(qn, kn) + np.dot(q_pe, kpes[p])) * scale)
            e = np.exp(np.array(scores) - max(scores))
            w = e / e.sum()
            V = np.zeros(128)
            for p in range(POS + 1):
                latv = quant_q8k_512(lat[p]) if v8 else lat[p]
                V += w[p] * (Vm.T @ latv)
            O[h * 128:(h + 1) * 128] = V
        return wo.T @ O

    for name, a1, a2, a3 in (("a exact_q,Q8L", False, True, True),
                             ("b Q8q,L", True, False, True),
                             ("c exact_q,L", False, False, True),
                             ("d Q8q,Q8L", True, True, True)):
        attn = run(a1, a2, a3)
        cos = float(np.dot(attn, ref) / (np.linalg.norm(attn) * np.linalg.norm(ref)))
        rmse = float(np.sqrt(np.mean((attn - ref) ** 2)))
        print("%-16s cos(ref)=%.8f rmse=%.6f ratio=%.6f" %
              (name, cos, rmse, np.linalg.norm(attn) / np.linalg.norm(ref)))


if __name__ == "__main__":
    main()
