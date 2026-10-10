#!/usr/bin/env python3
"""Validate the python MLA attention replication against the native op4/op5."""
import os
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from mla_attention_probe import POS, quant_q8k_512  # noqa: E402
from weight_parity_probe import GGUF, REF, dequant_q4_k, parse_gguf_tables, rd_ref  # noqa: E402


def rd_nat(p):
    d = open(p, "rb").read()
    nd = struct.unpack_from("<I", d, 16)[0]
    cnt = struct.unpack_from("<Q", d, 20 + 8 * nd)[0]
    off = 20 + 8 * nd + 8
    return np.array(struct.unpack_from("<%df" % cnt, d[off:off + cnt * 4]))


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

    mscale = (1 * (1 + 0.1 * np.log(40))) * (1 + 0.1 * 0.707 * np.log(40))
    scale = mscale * mscale / np.sqrt(192.0)

    O = np.zeros(2048)
    for h in range(16):
        qn = q[h * 192:h * 192 + 128]
        Vm = wkv_b[:, h * 256 + 128:(h + 1) * 256]
        Km = wkv_b[:, h * 256:h * 256 + 128]
        q_pe = np.zeros(64)
        for i in range(0, 64, 2):
            a = alpha(POS, i // 2)
            c, s = np.cos(a), np.sin(a)
            x, y = q[h * 192 + 128 + i], q[h * 192 + 128 + i + 1]
            q_pe[i] = x * c - y * s
            q_pe[i + 1] = x * s + y * c
        V = np.zeros(128)
        scores = []
        for p in range(POS + 1):
            kn = Km.T @ quant_q8k_512(lat[p])
            scores.append((np.dot(qn, kn) + np.dot(q_pe, kpes[p])) * scale)
        e = np.exp(np.array(scores) - max(scores))
        w = e / e.sum()
        for p in range(POS + 1):
            V += w[p] * (Vm.T @ quant_q8k_512(lat[p]))
        O[h * 128:(h + 1) * 128] = V

    nat_dir = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos2b"
    nat4 = nat5 = None
    for f in sorted(os.listdir(nat_dir)):
        p = os.path.join(nat_dir, f)
        h = open(p, "rb").read(10)
        if struct.unpack_from("<I", h, 0)[0] != 4:
            continue
        if "Attention_Output" in f and nat4 is None:
            nat4 = rd_nat(p)
        if "Linear_Output" in f and "op5" in f and nat5 is None:
            nat5 = rd_nat(p)

    def cos(a, b):
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    print("cos(python O, native op4) = %.8f" % cos(O, nat4))
    print("cos(python wo@O, native op5) = %.8f" % cos(wo.T @ O, nat5))
    print("norms: pyO %.4f nat4 %.4f | pyWo %.4f nat5 %.4f" %
          (np.linalg.norm(O), np.linalg.norm(nat4), np.linalg.norm(wo.T @ O), np.linalg.norm(nat5)))


if __name__ == "__main__":
    main()
