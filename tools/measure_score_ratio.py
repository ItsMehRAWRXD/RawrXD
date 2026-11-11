#!/usr/bin/env python3
"""Measure the effective score-scale ratio between llama reference and runtime.

Recovers llama attention weights via least squares from the reference post-wo
output (inverting wo), then compares logit-ratio score differences with the
native captured scores.
"""
import os
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from mla_attention_probe import quant_q8k_512  # noqa: E402
from weight_parity_probe import GGUF, REF, dequant_q4_k, parse_gguf_tables, rd_ref  # noqa: E402


def rd_nat_scores(path, layer=0):
    d = open(path, "rb").read()
    l = struct.unpack_from("<I", d, 4)[0]
    if l != layer:
        return None
    nd = struct.unpack_from("<I", d, 16)[0]
    dims = [struct.unpack_from("<q", d, 20 + 8 * j)[0] for j in range(nd)]
    cnt = struct.unpack_from("<Q", d, 20 + 8 * nd)[0]
    off = 20 + 8 * nd + 8
    return np.array(struct.unpack_from("<%df" % cnt, d, off)).reshape(dims)


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

    wo = deq("blk.0.attn_output.weight")
    wkv_b = deq("blk.0.attn_kv_b.weight")
    wo_inv = np.linalg.inv(wo.T)

    ratios = []
    for pos in (1, 2):
        lat = [rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_kv_cmpr.bin" % p))["v"]
               for p in range(pos + 1)]
        ref = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_attn_out.bin" % pos))["v"]
        pre = wo_inv @ ref
        # native scores
        nat_dir = (r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1"
                   if pos == 1 else
                   r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos2b")
        sc = None
        for f in sorted(os.listdir(nat_dir)):
            if "Attention_Scores" in f:
                v = rd_nat_scores(os.path.join(nat_dir, f))
                if v is not None:
                    sc = v
                    break
        for h in range(16):
            Vm = wkv_b[:, h * 256 + 128:(h + 1) * 256]
            Vs = np.stack([Vm.T @ quant_q8k_512(lat[p]) for p in range(pos + 1)], axis=1)
            w, *_ = np.linalg.lstsq(Vs, pre[h * 128:(h + 1) * 128], rcond=None)
            w = np.clip(w, 1e-6, None)
            s = sc[h]
            for i in range(pos + 1):
                for j in range(i + 1, pos + 1):
                    d_ll = np.log(w[i] / w[j])
                    d_our = s[i] - s[j]
                    if abs(d_our) > 1.0:
                        ratios.append(d_ll / d_our)
    ratios = np.array(ratios)
    print("n=%d  mean=%.5f  median=%.5f  std=%.5f  p10=%.4f  p90=%.4f" %
          (len(ratios), ratios.mean(), np.median(ratios), ratios.std(),
           np.percentile(ratios, 10), np.percentile(ratios, 90)))
    print("our scale = 0.214919  -> llama effective = %.6f" % (0.214919 * np.median(ratios)))
    for cand, name in ((1 / np.sqrt(75), "1/sqrt(75)"),
                       (1 / np.sqrt(74.2), "1/sqrt(74.2)"),
                       (1 / np.sqrt(64), "1/sqrt(64)"),
                       (1 / np.sqrt(192.0) * 1.3689, "attn_org/sqrt(192)"),
                       (0.538 * 1 / np.sqrt(192.0) * 2.9689, "0.538*mscale^2/sqrt(192)")):
        print("  candidate %-24s = %.6f" % (name, cand))


if __name__ == "__main__":
    main()
