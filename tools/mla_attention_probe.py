#!/usr/bin/env python3
"""Decide the exact MLA attention numerics llama.cpp uses.

Variants tested at layer 0, position 2 (all vs llama.cpp reference attn_out):
  (a) exact q_nope . (wk_b^T @ Q8(latent))      -- our current implementation
  (b) Q8(q_nope) . (wk_b^T @ latent)            -- absorbed path w/ partial-block q8
  (c) exact q_nope . (wk_b^T @ latent)          -- absorbed path, no q quantization
  (d) Q8(q_nope) . (wk_b^T @ Q8(latent))
"""
import os
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from weight_parity_probe import (GGUF, REF, dequant_q4_k, parse_gguf_tables,
                                 rd_ref)

NAT = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos2b"
HEADS = 16
NOPE = 128
ROPE = 64
RANK = 512
POS = 2
LAYER = 0


def rd_nat(p):
    d = open(p, "rb").read()
    nd = struct.unpack_from("<I", d, 16)[0]
    cnt = struct.unpack_from("<Q", d, 20 + 8 * nd)[0]
    off = 20 + 8 * nd + 8
    return (struct.unpack_from("<%df" % cnt, d[off:off + cnt * 4]))


def quant_q8k_128(x):
    """partial q8_K block of 128 elements (as ggml would for a 128-length vector)"""
    amax = 0.0
    mx = 0.0
    for v in x:
        if abs(v) > amax:
            amax, mx = abs(v), v
    if amax == 0.0:
        return np.zeros_like(x)
    isc = -127.0 / mx
    q = np.minimum(np.rint(isc * x).astype(np.int32), 127)
    return q.astype(np.float64) * (1.0 / isc)


def quant_q8k_512(x):
    amax = 0.0
    mx = 0.0
    for v in x:
        if abs(v) > amax:
            amax, mx = abs(v), v
    if amax == 0.0:
        return np.zeros_like(x)
    isc = -127.0 / mx
    q = np.minimum(np.rint(isc * x).astype(np.int32), 127)
    return q.astype(np.float64) * (1.0 / isc)


def main():
    kv, T, te = parse_gguf_tables(GGUF)
    ds = (te + 31) // 32 * 32
    raw = open(GGUF, "rb").read()

    def deq(name):
        t = T[name]
        n = int(np.prod(t["dims"]))
        off = ds + t["offset"]
        if t["type"] == 12:
            w = dequant_q4_k(raw[off:off + n // 256 * 144], n)
        else:
            w = np.frombuffer(raw[off:off + n * 4], dtype=np.float32).astype(np.float64)[:n]
        return w.reshape(t["dims"][0], t["dims"][1], order="F")

    wkv_b = deq("blk.0.attn_kv_b.weight")     # [512, 4096]
    wo = deq("blk.0.attn_output.weight")      # [2048, 2048]

    latents = [rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_kv_cmpr.bin" % p))["v"]
               for p in range(POS + 1)]
    kpes = [rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_k_pe.bin" % p))["v"]
            for p in range(POS + 1)]
    q = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_q.bin" % POS))["v"]

    # rope q_pe at POS with the same yarn alphas as the runtime
    def alpha(position, k):
        theta_extrap = position * (10000.0 ** (-2.0 * k / ROPE))
        theta_interp = 0.025 * theta_extrap
        corr_fast = ROPE * np.log(4096.0 / (32.0 * 2 * np.pi)) / (2 * np.log(10000.0))
        corr_slow = ROPE * np.log(4096.0 / (1.0 * 2 * np.pi)) / (2 * np.log(10000.0))
        low, high = np.floor(corr_fast), np.ceil(corr_slow)
        y = (k - low) / max(0.001, high - low)
        ramp = 1.0 if y <= 0 else (0.0 if y >= 1 else 1.0 - y)
        return theta_interp * (1 - ramp) + theta_extrap * ramp

    q_pe = np.zeros(ROPE)
    for i in range(0, ROPE, 2):
        a = alpha(POS, i // 2)
        c, s = np.cos(a), np.sin(a)
        x, y = q[NOPE + i], q[NOPE + i + 1]
        q_pe[i] = x * c - y * s
        q_pe[i + 1] = x * s + y * c

    # mscale
    mscale = (1 * (1 + 0.1 * np.log(40))) * (1 + 0.1 * 0.707 * np.log(40))
    scale = mscale * mscale / np.sqrt(192)

    # k_nope from latent (exact) and from quantized latent, per head
    k_nope_exact = np.zeros((HEADS, NOPE))
    k_nope_q8 = np.zeros((HEADS, NOPE))
    v_q8 = np.zeros((HEADS, NOPE))
    for h in range(HEADS):
        # wk_b rows for this head: latent(512) -> nope(128)
        Km = wkv_b[:, h * 256:h * 256 + 128]
        Vm = wkv_b[:, h * 256 + 128:(h + 1) * 256]
        for p in range(POS + 1):
            if p == POS:
                k_nope_exact[h] = Km.T @ latents[p]
                lq8 = quant_q8k_512(latents[p])
                k_nope_q8[h] = Km.T @ lq8
                v_q8[h] = Vm.T @ lq8

    ref_attn = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_attn_out.bin" % POS))["v"]
    nat_scores = None
    for f in sorted(os.listdir(NAT)):
        if "Attention_Scores" in f:
            d = open(os.path.join(NAT, f), "rb").read()
            layer, pos = struct.unpack_from("<II", d, 4)
            p = struct.unpack_from("<Q", d, 8)[0]
            if layer == LAYER:
                nat_scores = rd_nat(os.path.join(NAT, f))
                break
    print("native scores(h0):", np.round(nat_scores[:POS + 1], 5) if nat_scores is not None else None)

    out = {}
    for name, qn_mode, knp in (("a exact_q x Q8L", False, k_nope_q8),
                               ("b Q8q x L", True, k_nope_exact),
                               ("c exact_q x L", False, k_nope_exact),
                               ("d Q8q x Q8L", True, k_nope_q8)):
        O = np.zeros(2048)
        for h in range(HEADS):
            qn = q[h * 192:h * 192 + 128]
            if qn_mode:
                qn = quant_q8k_128(qn)
            scores = np.zeros(POS + 1)
            for p in range(POS + 1):
                if p == POS:
                    kn = knp[h]
                else:
                    # recompute per-position k_nope for older positions
                    Km = wkv_b[:, h * 256:h * 256 + 128]
                    if knp is k_nope_q8:
                        kn = Km.T @ quant_q8k_512(latents[p])
                    else:
                        kn = Km.T @ latents[p]
                s = np.dot(qn, kn) + np.dot(q_pe, kpes[p])
                scores[p] = s * scale
            e = np.exp(scores - scores.max())
            w = e / e.sum()
            V = np.zeros(128)
            for p in range(POS + 1):
                Vm = wkv_b[:, h * 256 + 128:(h + 1) * 256]
                V += w[p] * (Vm.T @ quant_q8k_512(latents[p]))
            O[h * 128:(h + 1) * 128] = V
        attn = wo.T @ O
        cos = float(np.dot(attn, ref_attn) / (np.linalg.norm(attn) * np.linalg.norm(ref_attn)))
        rmse = float(np.sqrt(np.mean((attn - ref_attn) ** 2)))
        print("variant %-16s cos(ref)=%.8f rmse=%.6f norm_ratio=%.6f" %
              (name, cos, rmse, np.linalg.norm(attn) / np.linalg.norm(ref_attn)))


if __name__ == "__main__":
    main()
