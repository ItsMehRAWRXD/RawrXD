#!/usr/bin/env python3
"""DEEP2_QWEN2_CPU_CORRECTNESS_001 — Q4K kernel adjudicator.

Independently judges three Q4K dot-product implementations for ONE
(engine_row, engine_col) cell against a float64 dequant-x reference:

  A  canonical dequant float dot            (ground truth)
  B  ggml vec_dot_q4_K_q8_K (canonical)    (what llama.cpp computes)
  C  Deep2 port as currently written       (what the engine computes)

Uses the engine's real SWIGLU vector from blk.4 as the activation, exactly as
the engine hot path sees it. Pure-python reference: no llama.cpp dependency.

Per the fail-closed law: C == B (or |C-B| small) means the int-dot path is
faithful and the 32B divergence lies elsewhere; C != B pins the defect to a
specific decode line (scales/utmp shuffle or q4 nibble layout).
"""
import importlib.util
import struct
import sys

import numpy as np

L4 = r"F:\~dev\rawrxd\scripts\qwen2_l4_reference.py"
spec = importlib.util.spec_from_file_location("l4", L4)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

tinfos, ds = m.parse_header(m.GGUF)
vecs = m.parse_vecs()
sw = vecs["SWIGLU"].astype(np.float64).reshape(1, -1)[0]

NAME = "blk.4.ffn_down.weight"
rows, cols = tinfos[NAME][0][0], tinfos[NAME][0][1]
bpr = rows // 256

with open(m.GGUF, "rb") as f:
    f.seek(ds + tinfos[NAME][2])
    raw = np.frombuffer(f.read(rows * bpr * 210), dtype=np.uint8).reshape(rows, -1)

assert raw.shape[1] == bpr * 210, f"unexpected row bytes {raw.shape[1]}"

kmask1 = 0x3F3F3F3F
kmask2 = 0x0F0F0F0F
kmask3 = 0x03030303


def unpack_scales(u32):
    """Return (scales[8], mins[8]) after the canonical utmp shuffle."""
    utmp = [w & 0xFFFFFFFF for w in u32] + [0]
    utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4)
    uaux = utmp[1] & kmask1
    utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4)
    utmp[2] = uaux
    utmp[0] &= kmask1
    sc = []
    mn = []
    for w in utmp:
        sc.append(w & 63)
        sc.append((w >> 8) & 63)
        mn.append((w >> 16) & 63)
        mn.append((w >> 24) & 63)
    return sc, mn


def q8k_block(xb):
    idx = int(np.argmax(np.abs(xb)))
    mx = xb[idx]
    if mx == 0:
        return 0.0, np.zeros(256, dtype=np.int64), np.zeros(16, dtype=np.int64)
    iscale = -127.0 / mx
    v = np.clip(np.round(iscale * xb).astype(np.int64), -127, 127)
    return 1.0 / iscale, v, v.reshape(16, 16).sum(axis=1)


def vec_dot_q4k_q8k_canonical(row_bytes, x):
    """ggml ggml_vec_dot_q4_K_q8_K generic — verbatim semantics."""
    total = 0.0
    for b in range(bpr):
        blk = row_bytes[b * 210:(b + 1) * 210]
        d = float(m.F16_TAB[struct.unpack("<H", blk[0:2])[0]])
        dmin = float(m.F16_TAB[struct.unpack("<H", blk[2:4])[0]])
        u32 = struct.unpack("<3I", blk[4:16])
        sc, mn = unpack_scales(u32)
        q4 = blk[16:144].astype(np.int64)

        aux8 = np.empty(256, dtype=np.int64)
        a = 0
        for j in range(4):
            for l in range(32):
                aux8[a + l] = q4[l] & 0xF
            a += 32
            for l in range(32):
                aux8[a + l] = q4[l] >> 4
            a += 32
            q4 = q4[32:]

        yd, yq, yb = q8k_block(x[b * 256:(b + 1) * 256])

        sumi = 0
        for j in range(16):
            sumi += int(yb[j]) * mn[j // 2]

        aux32 = np.zeros(8, dtype=np.int64)
        q8 = yq
        a = 0
        isb = 0
        for j in range(8):
            scale = sc[isb]
            isb += 1
            for r in range(4):
                aux16 = (q8[a:a + 8] * aux8[a:a + 8]).astype(np.int64)
                aux32 += scale * aux16
                a += 8
        total += d * yd * float(aux32.sum())
        total -= dmin * yd * float(sumi)
    return total


def deep2_vec_dot(row_bytes, x):
    """Verbatim transcription of QuantKernelRegistry.cpp vec_dot_q4_K_q8_K."""
    total = 0.0
    for b in range(bpr):
        blk = row_bytes[b * 210:(b + 1) * 210]
        d = float(m.F16_TAB[struct.unpack("<H", blk[0:2])[0]])
        dmin = float(m.F16_TAB[struct.unpack("<H", blk[2:4])[0]])
        q4 = blk[16:144].astype(np.int64)

        aux8 = np.empty(256, dtype=np.int64)
        a = 0
        for j in range(4):
            for l in range(32):
                aux8[a + l] = q4[l] & 0xF
            a += 32
            for l in range(32):
                aux8[a + l] = q4[l] >> 4
            a += 32
            q4 = q4[32:]

        u32 = struct.unpack("<3I", blk[4:16])
        utmp = [w & 0xFFFFFFFF for w in u32] + [0]
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4)
        uaux = utmp[1] & kmask1
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4)
        utmp[2] = uaux
        utmp[0] &= kmask1
        sc = []
        mn = []
        for w in utmp:
            sc.append(w & 63)
            sc.append((w >> 8) & 63)
            mn.append((w >> 16) & 63)
            mn.append((w >> 24) & 63)

        yd, yq, yb = q8k_block(x[b * 256:(b + 1) * 256])

        sumi = 0
        for j in range(16):
            sumi += int(yb[j]) * mn[j // 2]

        aux32 = np.zeros(8, dtype=np.int64)
        q8 = yq
        a = 0
        isb = 0
        for j in range(8):
            scale = sc[isb]
            isb += 1
            for r in range(4):
                aux16 = (q8[a:a + 8] * aux8[a:a + 8]).astype(np.int64)
                aux32 += scale * aux16
                a += 8
        total += d * yd * float(aux32.sum())
        total -= dmin * yd * float(sumi)
    return total


def canonical_dequant_row(row_bytes):
    vals = np.empty(rows, dtype=np.float64)
    for b in range(bpr):
        blk = row_bytes[b * 210:(b + 1) * 210]
        d = float(m.F16_TAB[struct.unpack("<H", blk[0:2])[0]])
        dmin = float(m.F16_TAB[struct.unpack("<H", blk[2:4])[0]])
        u32 = struct.unpack("<3I", blk[4:16])
        sc, mn = unpack_scales(u32)
        q4 = blk[16:144].astype(np.int64)
        for isb in range(8):
            srow = d * sc[isb]
            mrow = dmin * mn[isb]
            lo = q4[isb * 16:(isb + 1) * 16] & 0xF
            hi = q4[isb * 16:(isb + 1) * 16] >> 4
            vals[b * 256 + isb * 32:b * 256 + isb * 32 + 16] = srow * lo - mrow
            vals[b * 256 + isb * 32 + 16:b * 256 + isb * 32 + 32] = srow * hi - mrow
    return vals


def main():
    r = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    c = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    row_bytes = raw[c]
    x = sw
    W = canonical_dequant_row(raw[c])
    ref = float(np.asarray(np.dot(W, x)).ravel()[0])

    B = vec_dot_q4k_q8k_canonical(raw[c], sw)
    C = deep2_vec_dot(raw[c], sw)

    def fmt(v):
        return f"{v:+.6f}"

    print(f"CELL row={r} col={c} of ({rows},{cols})")
    print(f"REF_DEQUANT_F64  = {fmt(ref)}")
    print(f"B_GGML_INTDOT    = {fmt(B)}   |B-ref|={abs(B-ref):.4g} ({abs(B-ref)/max(abs(ref),1e-12)*100:.3f}%)")
    print(f"C_ENGINE_INTDOT  = {fmt(C)}   |C-ref|={abs(C-ref):.4g} ({abs(C-ref)/max(abs(ref),1e-12)*100:.3f}%)")
    print(f"|C-B|            = {abs(C-B):.6f}")

    verdict_B = "PASS" if abs(B - ref) <= max(0.01 * abs(ref), 0.5) else "FAIL"
    verdict_C = "PASS" if abs(C - ref) <= max(0.01 * abs(ref), 0.5) else "FAIL"
    faithful = "FAITHFUL" if abs(C - B) < 0.5 else "DIVERGENT"
    print(f"Q4K_GGML_CANONICAL_VS_REF={verdict_B}")
    print(f"Q4K_ENGINE_VS_REF={verdict_C}")
    print(f"ENGINE_VS_GGML={faithful}")


if __name__ == "__main__":
    main()








