#!/usr/bin/env python3
"""Compare the two accumulation orders for one REAL quantized matmul against our
own recorded output.

op5 of layer 0 (blk.0.attn_output.weight, q4_K, 2048x2048) maps the attention
output (MLA_PRE_WO, verified against llama.cpp at cos 0.9999998) to the layer's
output. Since the input is verified and the weights are the model's, comparing
(a) the runtime's dequantize-then-dot order with (b) ggml's blocked integer dot
followed by a single scale multiply tells us how much of the residual logit
error the kernel order can account for.

Usage: python kernel_order_ab.py <layer> <step> <native_dir>
"""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 1
ND = sys.argv[3] if len(sys.argv) > 3 else \
    r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current"
PHYS = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\genie_out\model.physical.txt"
GGUF = r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"

TENSOR = "blk.%d.attn_output.weight" % LAYER
IN = 2048
OUT = 2048


def read_record(path):
    b = open(path, "rb").read()
    _, _, _, ndim = struct.unpack_from("<IIQI", b, 0)
    off = 20 + 8 * ndim + 8
    return np.frombuffer(b[off:], dtype=np.float32).astype(np.float64)


def rec(label):
    for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label not in p or ("_p%d_" % STEP) not in p:
            continue
        if ("_l%d_" % LAYER) not in p and ("_l%02d_" % LAYER) not in p:
            continue
        return read_record(p)
    return None


def find_tensor():
    for line in open(PHYS, encoding="utf-8", errors="replace"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 5 and parts[0] == TENSOR:
            return parts[1], eval(parts[2]), int(parts[3]), int(parts[4])
    return None


def f16(b):
    return np.frombuffer(b, dtype=np.float16).astype(np.float32)


def dequant_q4k_block(block):
    """ggml Q4_K super-block (144 bytes, 256 elements) -> (q ints, scales, mins, d, dmin)."""
    d = f16(struct.unpack("<H", block[0:2])[0].to_bytes(2, "little"))[0]
    dmin = f16(struct.unpack("<H", block[2:4])[0].to_bytes(2, "little"))[0]
    scales = np.frombuffer(block[4:16], dtype=np.uint8)
    qs = np.frombuffer(block[16:144], dtype=np.uint8)
    kmax_scale = np.zeros(8)
    kmax_shift = np.zeros(8)
    sc = np.zeros(8)
    m = np.zeros(8)
    for i in range(8):
        v = int(scales[i])
        if v < 64:
            sc[i] = v & 63
            kmax_scale[i] = v & 63
            kmax_shift[i] = 0
            m[i] = 0
        else:
            sc[i] = (v & 63) | 64
            m[i] = 1
            kmax_scale[i] = v & 63
            kmax_shift[i] = 6
    is_valid = scales >= 64
    for i in range(8, 12):
        v = int(scales[i])
        sc[i - 4] += (v & 0x0F) * 8
        m[i - 4] += (v & 0x0F) * 8
        kmax_scale[i - 4] = 0
        kmax_shift[i - 4] = 0
    for i in range(12, 16):
        v = int(scales[i])
        sc[i - 8] += (v >> 4) * 8
        m[i - 8] += (v >> 4) * 8
        kmax_scale[i - 8] = 0
        kmax_shift[i - 8] = 0
    q = np.zeros(256, dtype=np.int32)
    for j in range(128):
        b = int(qs[j])
        q[j] = b & 0x0F
        q[j + 128] = b >> 4
    return q, sc.astype(np.float32), m.astype(np.float32), float(d), float(dmin)


def q8_quants(x, blk=32):
    """ggml quantize_row_q8_0: per-32 scale (fp16-rounded), roundf."""
    n = len(x)
    assert n % blk == 0
    q = np.zeros(n, dtype=np.int32)
    dsc = np.zeros(n // blk, dtype=np.float32)
    for b in range(n // blk):
        seg = x[b * blk:(b + 1) * blk]
        amax = float(np.abs(seg).max())
        d = amax / 127.0
        if d == 0:
            dsc[b] = 0.0
            continue
        dsc[b] = np.float32(np.float16(d))
        q[b * blk:(b + 1) * blk] = np.round(seg / d).astype(np.int32)
    return q, dsc


def main():
    tinfo = find_tensor()
    if not tinfo:
        print("tensor %s not found in %s" % (TENSOR, PHYS))
        return 1
    ttype, dims, nbytes, off = tinfo
    print("%s type=%s dims=%s bytes=%d offset=%d" % (TENSOR, ttype, dims, nbytes, off))
    nelem = dims[0] * dims[1]
    if dims[0] != IN or dims[1] != OUT:
        print("unexpected dims %s" % dims)
        return 1

    x = rec("MLA_PRE_WO_l%d_p%d" % (LAYER, STEP))
    native = None
    for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if "Linear_Output" not in p or ("_p%d_" % STEP) not in p:
            continue
        if ("_l%d_" % LAYER) not in p and ("_l%02d_" % LAYER) not in p:
            continue
        arr = read_record(p)
        if arr.size == OUT:
            native = arr
            break
    if x is None or native is None:
        print("missing input (%s) or recorded output (%s)"
              % (x is not None, native is not None))
        return 1
    x = x[:IN]
    print("input %d values, norm=%.6f" % (x.size, np.linalg.norm(x)))
    print("recorded output norm=%.6f first5=%s"
          % (np.linalg.norm(native), np.round(native[:5], 6).tolist()))

    with open(GGUF, "rb") as f:
        f.seek(off)
        raw = f.read(nbytes)

    nrows = OUT
    blocks_per_row = IN // 256
    bsz = nbytes // nrows
    print("row bytes=%d (%d super-blocks), total rows=%d" % (bsz, blocks_per_row, nrows))

    # path A: dequantize every weight, dot in float
    outA = np.zeros(nrows, dtype=np.float64)
    # path B: integer dot per super-block, then one scale multiply
    outB = np.zeros(nrows, dtype=np.float64)
    q8, d8 = q8_quants(x[:256].copy(), 32)  # per-32 activation scale (llama q8_0 path)

    for r in range(nrows):
        row = raw[r * bsz:(r + 1) * bsz]
        sa = 0.0
        sb = 0.0
        for b in range(blocks_per_row):
            blk = row[b * 144:(b + 1) * 144]
            q, sc, mn, d, dmin = dequant_q4k_block(blk)
            seg = q8[b * 32:(b + 1) * 32]
            db = float(d8[b])
            # A: each element dequantized then multiplied by the activation
            w = (q.astype(np.float64) - np.minimum(mn[np.arange(256) // 32].astype(np.float64), 1e9)
                 * 0)  # placeholder
            # ggml q4_K: value = d*sc - dmin*m
            w = np.zeros(256, dtype=np.float64)
            for j in range(8):
                lo = j * 32
                hi = lo + 32
                w[lo:hi] = float(d) * float(sc[j]) * (q[lo:hi].astype(np.float64) - float(mn[j]))
            sa += float(np.dot(w, x[b * 256:(b + 1) * 256].astype(np.float64)))
            # B: integer dot then scale
            sb += db * (float(d) * float(np.dot(
                (q - mn[np.arange(256) // 32].astype(np.int32)).astype(np.float32),
                seg.astype(np.float32))) - float(dmin * 0))
        outA[r] = sa
        outB[r] = sb

    def report(name, ref, arr):
        d = np.abs(arr - ref)
        print("%-8s cos=%.9f max|d|=%.8f rms=%.8f"
              % (name, float(arr @ ref / (np.linalg.norm(arr) * np.linalg.norm(ref))),
                 float(d.max()), float(np.sqrt((d * d).mean()))))

    print("\nagainst the runtime's recorded output:")
    report("A", native, outA)
    report("B", native, outB)
    print("\nfirst 6 A :", np.round(outA[:6], 6).tolist())
    print("first 6 B :", np.round(outB[:6], 6).tolist())
    print("first 6 rec:", np.round(native[:6], 6).tolist())
    return 0


if __name__ == "__main__":
    sys.exit(main())
