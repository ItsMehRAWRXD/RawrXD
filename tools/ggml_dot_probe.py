#!/usr/bin/env python3
"""Debug the ggml q4_K x q8_K emulation against reference activations."""
import glob
import os
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from weight_parity_probe import REF, GGUF, dequant_q4_k, parse_gguf_tables, rd_nat, rd_ref

NAT = r"F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\differential_pos0_token1"
Q8K_BYTES = 292  # 4 + 256 + 32


def fp16(h):
    return float(np.frombuffer(np.uint16(h).tobytes(), dtype=np.float16)[0])


def quantize_row_q8_K(x):
    """returns (d[256-blocks], int8 qs, bsums)"""
    n = len(x)
    assert n % 256 == 0
    nb = n // 256
    d = np.zeros(nb)
    qs = np.zeros((nb, 256), dtype=np.int32)
    bs = np.zeros((nb, 16), dtype=np.int32)
    for i in range(nb):
        xb = x[i * 256:(i + 1) * 256]
        amax, mx = 0.0, 0.0
        for v in xb:
            if abs(v) > amax:
                amax, mx = abs(v), v
        if amax == 0.0:
            continue
        isc = -127.0 / mx
        q = np.rint(isc * xb).astype(np.int32)
        q = np.minimum(q, 127)
        qs[i] = q
        d[i] = 1.0 / isc
        for j in range(16):
            bs[i, j] = int(q[j * 16:(j + 1) * 16].sum())
    return d, qs, bs


def sc_mn(raw12):
    sc = [0] * 8
    mn = [0] * 8
    for j in range(8):
        if j < 4:
            sc[j] = raw12[j] & 63
            mn[j] = raw12[j + 4] & 63
        else:
            sc[j] = (raw12[j + 4] & 0x0F) | ((raw12[j - 4] >> 6) << 4)
            mn[j] = (raw12[j + 4] >> 4) | ((raw12[j] >> 6) << 4)
    return sc, mn


def main():
    kv, T, te = parse_gguf_tables(GGUF)
    ds = (te + 31) // 32 * 32
    raw = np.frombuffer(open(GGUF, "rb").read(), dtype=np.uint8)

    recs = {}
    for p in glob.glob(os.path.join(NAT, "*.bin")):
        h = open(p, "rb").read(40)
        recs.setdefault(struct.unpack_from("<I", h, 0)[0], []).append(p)
    op1 = rd_nat(recs[1][0])["v"].astype(np.float64)
    print("op1[:4]", op1[:4])

    name = "blk.0.attn_q.weight"
    t = T[name]
    hidden, count = t["dims"]
    off = ds + t["offset"]
    nbpr = hidden // 256
    block_bytes = nbpr * 144
    blocks = raw[off:off + count * block_bytes].reshape(count, nbpr, 144)

    d, qs, bs = quantize_row_q8_K(op1)
    deq_row = (qs * d[:, None]).flatten()
    print("q8 dequant err:", np.sqrt(np.mean((deq_row - op1) ** 2)), "norm", np.linalg.norm(deq_row))

    refq = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p00_q.bin"))["v"]
    natq = rd_nat(recs[3][0])["v"]
    exq = rd_nat(recs[3][0])["v"]

    # variant A: integer ggml dot; variant B: dequantized dot using quantized row
    w_dq = np.zeros((hidden, count), dtype=np.float64)
    for j in range(count):
        w_dq[:, j] = dequant_q4_k(blocks[j].tobytes(), hidden)
    b_out = w_dq.T @ deq_row
    print("B: dequant q8 row: cos(ref)=%.10f rmse=%.6f | cos(exact)=%.10f" %
          (np.dot(b_out, refq) / (np.linalg.norm(b_out) * np.linalg.norm(refq)),
           np.sqrt(np.mean((b_out - refq) ** 2)),
           np.dot(b_out, exq) / (np.linalg.norm(b_out) * np.linalg.norm(exq))))

    aux8 = np.zeros((count, 256), dtype=np.int32)
    for j in range(count):
        for bi in range(nbpr):
            qs_b = blocks[j, bi, 16:144].astype(np.int32)
            base = bi * 256
            for jg in range(4):
                q32 = qs_b[jg * 32:(jg + 1) * 32]
                aux8[j, base + jg * 64:base + jg * 64 + 32] = q32 & 0xF
                aux8[j, base + jg * 64 + 32:base + jg * 64 + 64] = q32 >> 4
    a_out = np.zeros(count)
    for j in range(count):
        acc = 0.0
        for bi in range(nbpr):
            blk = blocks[j, bi]
            dw = fp16(int(blk[0]) | int(blk[1]) << 8)
            dmw = fp16(int(blk[2]) | int(blk[3]) << 8)
            sc, mn = sc_mn(blk[4:16])
            q8 = qs[bi]
            a = aux8[j, bi * 256:(bi + 1) * 256]
            term = 0
            for sub in range(8):
                term += sc[sub] * int(np.dot(q8[sub * 32:(sub + 1) * 32], a[sub * 32:(sub + 1) * 32]))
            sumi = 0
            for k in range(16):
                sumi += int(bs[bi][k]) * mn[k // 2]
            acc += dw * d[bi] * term
            acc -= dmw * d[bi] * sumi
        a_out[j] = acc
    print("A: integer ggml: cos(ref)=%.10f rmse=%.6f | cos(exact)=%.10f" %
          (np.dot(a_out, refq) / (np.linalg.norm(a_out) * np.linalg.norm(refq)),
           np.sqrt(np.mean((a_out - refq) ** 2)),
           np.dot(a_out, exq) / (np.linalg.norm(a_out) * np.linalg.norm(exq))))
    print("A[:6]", np.round(a_out[:6], 5), "B[:6]", np.round(b_out[:6], 5), "ref[:6]", np.round(refq[:6], 5))
    print("exact norm %.6f  B norm %.6f  A norm %.6f" %
          (np.linalg.norm(exq), np.linalg.norm(b_out), np.linalg.norm(a_out)))


if __name__ == "__main__":
    main()
