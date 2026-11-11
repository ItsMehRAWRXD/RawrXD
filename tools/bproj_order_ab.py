#!/usr/bin/env python3
"""Kernel-order A/B on a REAL matmul with a REAL reference.

The MLA B projection (blk.N.attn_kv_b.weight, q4_K) maps the cached latent to the
up-projected K/V. llama.cpp dumps its own output for that matmul
(probe_stepNN_kv_up_lNN.bin) and the runtime recorder captured the native output
(MLA_expanded). This computes, for the same input:

  A  the runtime order  - dequantize every weight element, dot in float64
  B  ggml order         - q8_K quantize the activation, integer dot per
                          256-block with 8 accumulators, one scale multiply per
                          block (ggml_vec_dot_q4_K_q8_K)

and scores both against llama.cpp. B is run twice: with the activation scale
kept in fp32 and rounded to fp16, which decides that convention too.
"""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 1
ND = os.environ.get("ND",
    r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current")
PHYS = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\genie_out\model.physical.txt"
GGUF = r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
PROBE = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"


def read_record(path):
    b = open(path, "rb").read()
    _, _, _, ndim = struct.unpack_from("<IIQI", b, 0)
    off = 20 + 8 * ndim + 8
    return np.frombuffer(b[off:], dtype=np.float32).astype(np.float64)


def rec(label, layer):
    tags = ("_l%d_" % layer, "_l%02d_" % layer)
    for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label not in p or ("_p%d_" % STEP) not in p:
            continue
        if not any(t in p for t in tags):
            continue
        return read_record(p)
    return None


def find_tensor(name):
    for line in open(PHYS, encoding="utf-8", errors="replace"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 5 and parts[0] == name:
            return parts[1], eval(parts[2]), int(parts[3]), int(parts[4])
    return None


def scales_min_k4(scales12):
    """ggml get_scale_min_k4 for j = 0..7."""
    out = []
    u = np.zeros(4, dtype=np.uint32)
    raw = np.frombuffer(scales12, dtype=np.uint8).copy()
    for j in range(8):
        if j < 4:
            d = int(raw[j]) & 63
            m = int(raw[j + 4]) & 63
        else:
            d = (int(raw[j + 4]) & 0x0F) | ((int(raw[j - 4]) >> 6) << 4)
            m = (int(raw[j + 4]) >> 4) | ((int(raw[j]) >> 6) << 4)
        out.append((d, m))
    return out


def fp16(bits):
    """ggml_fp16_to_fp32: decode an IEEE half-precision bit pattern."""
    return float(np.frombuffer(struct.pack("<H", int(bits) & 0xFFFF),
                                dtype=np.float16)[0])


def q8k_quant(x, scale_fp16):
    """ggml q8_K over one 256 block: one scale + bsums per 16."""
    x = np.asarray(x, dtype=np.float64)
    amax = float(np.abs(x).max())
    d = amax / 127.0
    if d == 0.0:
        return np.zeros(256, dtype=np.int32), 0.0, np.zeros(16, dtype=np.int32)
    d_use = fp16(d) if scale_fp16 else np.float32(d)
    q = np.round(x / d).astype(np.int32)
    q = np.clip(q, -128, 127)
    bsums = q.reshape(16, 16).sum(axis=1).astype(np.int32)
    return q, float(d_use), bsums


def q4k_row_dot_ggml(row, act, act_q8, act_d, act_bsums, nblk=8):
    """ggml_vec_dot_q4_K_q8_K for one 2048-element row (8 super-blocks)."""
    sums = np.zeros(8, dtype=np.float64)
    sumf = 0.0
    for b in range(nblk):
        blk = row[b * 144:(b + 1) * 144]
        d = float(fp16(struct.unpack("<H", blk[0:2])[0]))
        dmin = float(fp16(struct.unpack("<H", blk[2:4])[0]))
        sm = scales_min_k4(blk[4:16])
        qs = np.frombuffer(blk[16:144], dtype=np.uint8)
        a = np.zeros(256, dtype=np.int32)
        for j in range(4):
            a[j * 64:j * 64 + 32] = (qs[j * 32:(j + 1) * 32] & 0x0F).astype(np.int32)
            a[j * 64 + 32:j * 64 + 64] = (qs[j * 32:(j + 1) * 32] >> 4).astype(np.int32)
        q8 = act_q8[b * 256:(b + 1) * 256]
        q8_d = float(act_d[b])
        bsums = act_bsums[b]
        # sumi = sum over the 16 sub-groups of bsums[j]*mins[j/2]
        sumi = sum(bsums[j] * sm[j // 2][1] for j in range(16))
        aux32 = np.zeros(8, dtype=np.int32)
        is_ = 0
        for sub in range(8):
            scale = sm[is_][0]
            is_ += 1
            for g in range(4):
                for l in range(8):
                    aux32[l] += scale * int(q8[sub * 32 + g * 8 + l]) * int(a[sub * 32 + g * 8 + l])
        dd = d * q8_d
        sums += dd * aux32
        sumf -= (dmin * q8_d) * sumi
    return float(sumf + sums.sum())


def q4k_row_dot_dequant(row, act, nblk=8):
    out = 0.0
    for b in range(nblk):
        blk = row[b * 144:(b + 1) * 144]
        d = float(fp16(struct.unpack("<H", blk[0:2])[0]))
        dmin = float(fp16(struct.unpack("<H", blk[2:4])[0]))
        sm = scales_min_k4(blk[4:16])
        qs = np.frombuffer(blk[16:144], dtype=np.uint8)
        a = np.zeros(256, dtype=np.int32)
        for j in range(4):
            a[j * 64:j * 64 + 32] = (qs[j * 32:(j + 1) * 32] & 0x0F).astype(np.int32)
            a[j * 64 + 32:j * 64 + 64] = (qs[j * 32:(j + 1) * 32] >> 4).astype(np.int32)
        w = np.zeros(256, dtype=np.float64)
        for sub in range(8):
            sc, mn = sm[sub]
            for k in range(32):
                idx = sub * 32 + k
                w[idx] = d * sc * float(a[idx]) - dmin * mn
        out += float(np.dot(w, act[b * 256:(b + 1) * 256]))
    return out


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


def main():
    tin = "blk.%d.attn_kv_b.weight" % LAYER
    info = find_tensor(tin)
    if not info:
        print("tensor %s not found" % tin)
        return 1
    ttype, dims, nbytes, off = info
    IN, OUTR = dims if len(dims) == 2 else (dims[0], dims[1])
    print("%s %s dims=%s bytes=%d off=%d" % (tin, ttype, dims, nbytes, off))

    latent = rec("MLA_kv_latent_l%d_p%d" % (LAYER, STEP), LAYER)
    native = rec("MLA_expanded_l%d_p%d" % (LAYER, STEP), LAYER)
    if latent is None or native is None:
        print("missing latent (%s) or expanded (%s)" % (latent is not None, native is not None))
        return 1
    latent = latent[:IN]
    ref_raw = open(os.path.join(PROBE, "probe_step%02d_kv_up_l%02d.bin" % (STEP, LAYER)), "rb").read()
    nev = struct.unpack("<4q", ref_raw[4:36])
    ref = np.frombuffer(ref_raw[68:], dtype=np.float32).astype(np.float64)
    print("latent %d (norm %.6f), native expanded %d, llama kv_up %d ne=%s"
          % (latent.size, np.linalg.norm(latent), native.size, ref.size, list(nev)))

    with open(GGUF, "rb") as f:
        # model.physical.txt records offsets relative to the tensor data section
        data_start = 3996416
        f.seek(off + data_start)
        raw = f.read(nbytes)
    bsz = nbytes // OUTR
    nrows = min(OUTR, 32)          # first 32 output rows is enough signal

    # q8_K quantize the activation once for the whole vector
    q8all = np.zeros(IN, dtype=np.int32)
    dall = np.zeros(IN // 256, dtype=np.float64)
    bsumall = np.zeros((IN // 256, 16), dtype=np.int32)
    for b in range(IN // 256):
        q, dq, bs = q8k_quant(latent[b * 256:(b + 1) * 256], scale_fp16=False)
        q8all[b * 256:(b + 1) * 256] = q
        dall[b] = dq
        bsumall[b] = bs
    q8f = np.zeros(IN, dtype=np.int32)
    dalf = np.zeros(IN // 256, dtype=np.float64)
    for b in range(IN // 256):
        q, dq, bs = q8k_quant(latent[b * 256:(b + 1) * 256], scale_fp16=True)
        q8f[b * 256:(b + 1) * 256] = q
        dalf[b] = dq

    A = np.zeros(nrows)
    B = np.zeros(nrows)
    Bf = np.zeros(nrows)
    for r in range(nrows):
        row = raw[r * bsz:(r + 1) * bsz]
        A[r] = q4k_row_dot_dequant(row, latent, IN // 256)
        B[r] = q4k_row_dot_ggml(row, latent, q8all, dall, bsumall, IN // 256)
        Bf[r] = q4k_row_dot_ggml(row, latent, q8f, dalf, bsumall, IN // 256)

    nat = native[:nrows]
    llm = ref[:nrows] if ref.size >= nrows else native[:nrows]
    n = min(nat.size, llm.size)
    print("\nfirst %d output rows vs native recording and llama's own kv_up:" % n)
    print("%-10s cos(native) max|d|(native) | cos(llama) max|d|(llama)"
          % "order")
    for name, arr in (("A", A), ("B(f32)", B), ("B(fp16)", Bf)):
        c_n = cos(arr[:n], nat[:n])
        d_n = float(np.abs(arr[:n] - nat[:n]).max())
        c_l = cos(arr[:n], llm[:n])
        d_l = float(np.abs(arr[:n] - llm[:n]).max())
        print("%-10s %10.7f %15.8f | %9.7f %13.8f" % (name, c_n, d_n, c_l, d_l))
    return 0


if __name__ == "__main__":
    sys.exit(main())
