#!/usr/bin/env python3
"""Test whether the reference 'attn_out' stage is the pre-wo attention output."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from mla_attention_probe import quant_q8k_512, rd_nat  # noqa: E402
from weight_parity_probe import GGUF, REF, dequant_q4_k, parse_gguf_tables, rd_ref  # noqa: E402


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

    wkv_b = deq("blk.0.attn_kv_b.weight")
    wo = deq("blk.0.attn_output.weight")
    lat = [rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_kv_cmpr.bin" % p))["v"]
           for p in range(3)]
    ref = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p02_attn_out.bin"))["v"]

    def cos(a, b):
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    O = np.zeros(2048)
    for h in range(16):
        Vm = wkv_b[:, h * 256 + 128:(h + 1) * 256]
        O[h * 128:(h + 1) * 128] = Vm.T @ quant_q8k_512(lat[2])
    print("cos(ref, V(pos2) pre-wo) = %.8f" % cos(O, ref))
    print("cos(ref, wo@V)          = %.8f" % cos(wo.T @ O, ref))
    print("norms: ref %.4f  V %.4f  woV %.4f" %
          (np.linalg.norm(ref), np.linalg.norm(O), np.linalg.norm(wo.T @ O)))

    # compare with our captured attention output (pre-wo, op4)
    nat_dir = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos2b"
    for f in sorted(os.listdir(nat_dir)):
        if "Attention_Output" in f:
            v = rd_nat(os.path.join(nat_dir, f))
            if v is not None and len(v) == 2048:
                print("cos(ref, native op4 pre-wo) = %.8f  rmse=%.6f" %
                      (cos(v, ref), float(np.sqrt(np.mean((v - ref) ** 2)))))
                print("cos(ref, wo@nat_op4)        = %.8f" % cos(wo.T @ v, ref))
                break


if __name__ == "__main__":
    main()
