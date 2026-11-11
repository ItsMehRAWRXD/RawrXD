#!/usr/bin/env python3
"""REFERENCE_DIFFERENTIAL_002: decode llama.cpp KV-cache views with the
authoritative layout from llama-kv-cache.cpp get_k().

Cache layout (per stream/layer): [slot][head][head_dim], i.e. slot stride =
n_embd_k_gqa elements, head stride = n_embd_head_k elements. The probe dump
writes rows in the registered tensor's (ne1, ne2) order with per-row offsets
computed from nb, so the flat file is [ne1][ne2][ne0].
"""
import os
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from weight_parity_probe import GGUF, REF, dequant_q4_k, parse_gguf_tables, rd_ref  # noqa: E402


def read_probe(path):
    raw = open(path, "rb").read()
    assert raw[:4] == b"RAWH"
    ne = struct.unpack("<4q", raw[4:36])
    nb = struct.unpack("<4Q", raw[36:68])
    v = np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)
    n_rows = 1
    for d in range(1, 4):
        n_rows *= ne[d]
    return ne, nb, v.reshape(n_rows, ne[0])


def layout(ne, nb):
    """Map each dumped row index to its (ne1, ne2) coordinates and offset."""
    out = []
    n_rows = 1
    for d in range(1, 4):
        n_rows *= ne[d]
    for r in range(n_rows):
        off = 0
        rem = r
        coords = [0, 0, 0, 0]
        for d in (3, 2, 1):
            if ne[d] <= 1:
                continue
            per = 1
            for dd in range(1, d):
                per *= ne[dd]
            c = rem // per
            rem = rem % per
            coords[d] = c
            off += c * nb[d]
        out.append((coords[1], coords[2], off // (nb[0] // 4 if nb[0] % 4 == 0 else 1)))
    return out


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else \
        r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_probe"
    step = sys.argv[2] if len(sys.argv) > 2 else "01"

    ne, nb, K = read_probe(os.path.join(d, "probe_step%s_k_attn_l00.bin" % step))
    print("k_attn ne=%s nb=%s rows=%d rowlen=%d" % (ne, nb, K.shape[0], K.shape[1]))
    print("  ne1=%d (stride %d bytes = %d elems), ne2=%d (stride %d bytes)" %
          (ne[1], nb[1], nb[1] // 2, ne[2], nb[2]))
    # rows are ordered r with offset (r/ne2)*nb1 + (r%ne2)*nb2
    # => flat file is [ne1][ne2][dim] = [slot][head][dim] for ne1=slots
    slots = ne[1]
    heads = ne[2]
    dim = ne[0]
    Kc = K.reshape(slots, heads, dim)  # [slot][head][dim]
    norms = np.linalg.norm(Kc, axis=2)
    print("  per-slot total ||K||:", [round(float(x), 3) for x in norms.sum(axis=1)[:6]])
    nz = np.argwhere(norms > 1e-6)
    print("  nonzero (slot, head) pairs:", nz[:8].tolist())
    print("  slot 0 head0 K[:8]:", np.round(Kc[0, 0, :8], 5).tolist())
    print("  slot 1 head0 K[:8]:", np.round(Kc[1, 0, :8], 5).tolist())

    nev, nbv, V = read_probe(os.path.join(d, "probe_step%s_v_attn_l00.bin" % step))
    print("v_attn ne=%s nb=%s" % (nev, nbv))
    vs = nev[1] if nev[1] > 1 else 1
    vh = nev[2] if nev[2] > 1 else 1
    Vc = V.reshape(vs, vh, nev[0])
    print("  v shape [%d slots][%d heads][%d dim]" % (vs, vh, nev[0]))
    vnorm = np.linalg.norm(Vc, axis=2)
    nzv = np.argwhere(vnorm > 1e-6)
    print("  nonzero v (slot, head):", nzv[:8].tolist())
    print("  v slot0 head0[:8]:", np.round(Vc[0, 0, :8], 5).tolist())

    neq, nbq, Q = read_probe(os.path.join(d, "probe_step%s_q_attn_l00.bin" % step))
    print("q_attn ne=%s" % (neq,))
    qh = neq[2] if neq[2] > 1 else 1
    Qc = Q.reshape(qh, neq[0])
    print("  q[head][dim] head0[:8]:", np.round(Qc[0, :8], 5).tolist())


if __name__ == "__main__":
    main()
