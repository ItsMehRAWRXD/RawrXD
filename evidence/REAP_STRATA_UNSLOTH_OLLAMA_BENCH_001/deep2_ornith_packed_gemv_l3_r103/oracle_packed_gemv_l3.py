#!/usr/bin/env python3
"""Independent CPU oracle for Ornith MoE PACKED_GEMV @ L3.
Q4_K x Q8_K (ggml mul_mat path) vs dumped MOE_GATE/UP/DOWN.
Not llama.cpp. PROMOTE=0.
"""
from __future__ import annotations

import argparse
import glob
import math
import os
import struct
import sys
from typing import List, Tuple

QK_K = 256
Q4K_BLOCK = 144  # d,dmin,scales[12],qs[128]
Q6K_BLOCK = 210  # ql[128],qh[64],scales[16],d
GGML_Q4_K = 12
GGML_Q6_K = 14


def f16_to_f32(h: int) -> float:
    s = (h >> 15) & 1
    e = (h >> 10) & 0x1F
    f = h & 0x3FF
    if e == 0:
        if f == 0:
            return -0.0 if s else 0.0
        # subnormal
        return ((-1.0) ** s) * (f / 1024.0) * (2.0 ** -14)
    if e == 31:
        return float("nan") if f else ((-1.0) ** s) * float("inf")
    return ((-1.0) ** s) * (1.0 + f / 1024.0) * (2.0 ** (e - 15))


def nearest_int(fval: float) -> int:
    val = fval + 12582912.0
    i = struct.unpack("<i", struct.pack("<f", val))[0]
    return (i & 0x007FFFFF) - 0x00400000


def read_f32(path: str) -> List[float]:
    with open(path, "rb") as f:
        b = f.read()
    n = len(b) // 4
    return list(struct.unpack(f"<{n}f", b[: n * 4]))


def ulp_diff(a: float, b: float) -> int:
    if not math.isfinite(a) or not math.isfinite(b):
        return 2**31 - 1
    ai = struct.unpack("<I", struct.pack("<f", a))[0]
    bi = struct.unpack("<I", struct.pack("<f", b))[0]
    if ai & 0x80000000:
        ai = 0x80000000 - (ai & 0x7FFFFFFF)
    if bi & 0x80000000:
        bi = 0x80000000 - (bi & 0x7FFFFFFF)
    return abs(ai - bi)


def find_bin(dump_dir: str, key: str) -> str | None:
    pats = [
        os.path.join(dump_dir, f"deep2_{key}_*.bin"),
        os.path.join(dump_dir, f"*{key}*.bin"),
    ]
    hits: List[str] = []
    for p in pats:
        hits.extend(glob.glob(p))
    hits = sorted(set(hits))
    return hits[0] if hits else None


def quantize_row_q8_K(x: List[float]) -> Tuple[List[float], List[int], List[int]]:
    """Return parallel lists: d[nb], qs[nb*256], bsums[nb*16]."""
    assert len(x) % QK_K == 0
    nb = len(x) // QK_K
    ds: List[float] = []
    qs: List[int] = []
    bsums: List[int] = []
    for i in range(nb):
        chunk = x[i * QK_K : (i + 1) * QK_K]
        amax = 0.0
        maxv = 0.0
        for v in chunk:
            ax = abs(v)
            if ax > amax:
                amax = ax
                maxv = v
        if amax == 0.0:
            ds.append(0.0)
            qs.extend([0] * QK_K)
            bsums.extend([0] * 16)
            continue
        iscale = -127.0 / maxv
        row = []
        for v in chunk:
            vi = nearest_int(iscale * v)
            if vi > 127:
                vi = 127
            if vi < -128:
                vi = -128
            row.append(vi)
        qs.extend(row)
        for j in range(16):
            s = sum(row[j * 16 : (j + 1) * 16])
            bsums.append(s)
        ds.append(1.0 / iscale)
    return ds, qs, bsums


def vec_dot_q4_K_q8_K(w: bytes, w_off: int, x_d: List[float], x_qs: List[int],
                      x_bsums: List[int], cols: int) -> float:
    nb = cols // QK_K
    kmask1 = 0x3F3F3F3F
    kmask2 = 0x0F0F0F0F
    kmask3 = 0x03030303
    sumf = 0.0
    sums = [0.0] * 8
    for i in range(nb):
        blk = w[w_off + i * Q4K_BLOCK : w_off + (i + 1) * Q4K_BLOCK]
        d = f16_to_f32(struct.unpack_from("<H", blk, 0)[0])
        dmin = f16_to_f32(struct.unpack_from("<H", blk, 2)[0])
        scales_raw = blk[4:16]
        qs = blk[16:144]
        utmp = list(struct.unpack("<III", scales_raw[:12])) + [0]
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4)
        uaux = utmp[1] & kmask1
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4)
        utmp[2] = uaux
        utmp[0] &= kmask1
        sc = struct.pack("<IIII", *utmp)
        scales = sc[0:8]
        mins = sc[8:16]

        aux8 = []
        q4 = qs
        for j in range(4):
            chunk = q4[j * 32 : (j + 1) * 32]
            aux8.extend([b & 0xF for b in chunk])
            aux8.extend([b >> 4 for b in chunk])

        q8 = x_qs[i * QK_K : (i + 1) * QK_K]
        bsum = x_bsums[i * 16 : (i + 1) * 16]
        sumi = 0
        for j in range(16):
            sumi += bsum[j] * mins[j // 2]

        aux32 = [0] * 8
        a = 0
        q = 0
        is_ = 0
        for j in range(8):
            scale = scales[is_]
            is_ += 1
            for r in range(4):
                for l in range(8):
                    aux32[l] += scale * q8[q + l] * aux8[a + l]
                q += 8
                a += 8
        dd = d * x_d[i]
        for l in range(8):
            sums[l] += dd * float(aux32[l])
        sumf -= dmin * x_d[i] * float(sumi)
    for l in range(8):
        sumf += sums[l]
    return sumf


def gemv_q4k_q8k(w: bytes, x: List[float], rows: int, cols: int) -> List[float]:
    assert cols % QK_K == 0
    x_d, x_qs, x_bsums = quantize_row_q8_K(x)
    blocks_per_row = cols // QK_K
    out = [0.0] * rows
    for r in range(rows):
        off = r * blocks_per_row * Q4K_BLOCK
        out[r] = vec_dot_q4_K_q8_K(w, off, x_d, x_qs, x_bsums, cols)
    return out


def vec_dot_q6_K_q8_K(w: bytes, w_off: int, x_d: List[float], x_qs: List[int],
                      cols: int) -> float:
    nb = cols // QK_K
    sums = [0.0] * 8
    for i in range(nb):
        blk = w[w_off + i * Q6K_BLOCK : w_off + (i + 1) * Q6K_BLOCK]
        ql = blk[0:128]
        qh = blk[128:192]
        scales = struct.unpack("<16b", blk[192:208])
        d = f16_to_f32(struct.unpack_from("<H", blk, 208)[0])
        aux8 = [0] * 256
        a = 0
        q4 = 0
        qh_i = 0
        for j in range(0, 256, 128):
            for l in range(32):
                aux8[a + l + 0] = ((ql[q4 + l] & 0xF) | (((qh[qh_i + l] >> 0) & 3) << 4)) - 32
                aux8[a + l + 32] = ((ql[q4 + l + 32] & 0xF) | (((qh[qh_i + l] >> 2) & 3) << 4)) - 32
                aux8[a + l + 64] = ((ql[q4 + l] >> 4) | (((qh[qh_i + l] >> 4) & 3) << 4)) - 32
                aux8[a + l + 96] = ((ql[q4 + l + 32] >> 4) | (((qh[qh_i + l] >> 6) & 3) << 4)) - 32
            a += 128
            q4 += 64
            qh_i += 32
        q8 = x_qs[i * QK_K : (i + 1) * QK_K]
        aux32 = [0] * 8
        aa = 0
        qq = 0
        is_ = 0
        for j in range(256 // 16):
            scale = scales[is_]
            is_ += 1
            for _rep in range(2):
                for l in range(8):
                    aux32[l] += scale * q8[qq + l] * aux8[aa + l]
                qq += 8
                aa += 8
        dd = d * x_d[i]
        for l in range(8):
            sums[l] += dd * float(aux32[l])
    return sum(sums)


def gemv_q6k_q8k(w: bytes, x: List[float], rows: int, cols: int) -> List[float]:
    assert cols % QK_K == 0
    x_d, x_qs, _bsums = quantize_row_q8_K(x)
    blocks_per_row = cols // QK_K
    out = [0.0] * rows
    for r in range(rows):
        off = r * blocks_per_row * Q6K_BLOCK
        out[r] = vec_dot_q6_K_q8_K(w, off, x_d, x_qs, cols)
    return out


def gemv_dispatch(w: bytes, x: List[float], rows: int, cols: int, ttype: int) -> List[float]:
    if ttype == GGML_Q4_K:
        return gemv_q4k_q8k(w, x, rows, cols)
    if ttype == GGML_Q6_K:
        return gemv_q6k_q8k(w, x, rows, cols)
    raise SystemExit(f"unsupported quant type={ttype}")


def swiglu(gate: List[float], up: List[float]) -> List[float]:
    # silu(gate)*up
    out = []
    for g, u in zip(gate, up):
        sig = 1.0 / (1.0 + math.exp(-g)) if math.isfinite(g) else 0.0
        out.append((g * sig) * u)
    return out


def load_gguf_meta(gguf: str):
    with open(gguf, "rb") as f:
        assert f.read(4) == b"GGUF"
        ver = struct.unpack("<I", f.read(4))[0]
        n_tensors, n_kv = struct.unpack("<QQ", f.read(16))

        def read_str() -> bytes:
            (ln,) = struct.unpack("<Q", f.read(8))
            return f.read(ln)

        def skip_val(t: int) -> None:
            if t in (0, 1, 7):
                f.read(1)
            elif t in (2, 3):
                f.read(2)
            elif t in (4, 5, 6):
                f.read(4)
            elif t in (10, 11, 12):
                f.read(8)
            elif t == 8:
                read_str()
            elif t == 9:
                (at,) = struct.unpack("<I", f.read(4))
                (al,) = struct.unpack("<Q", f.read(8))
                for _ in range(al):
                    skip_val(at)
            else:
                raise SystemExit(f"kv {t}")

        for _ in range(n_kv):
            read_str()
            (vt,) = struct.unpack("<I", f.read(4))
            skip_val(vt)
        tensors = []
        for _ in range(n_tensors):
            tname = read_str().decode()
            (ndims,) = struct.unpack("<I", f.read(4))
            dims = struct.unpack(f"<{ndims}Q", f.read(8 * ndims))
            (ttype,) = struct.unpack("<I", f.read(4))
            (toff,) = struct.unpack("<Q", f.read(8))
            tensors.append((tname, dims, ttype, toff))
        data_start = f.tell()
        if data_start % 32:
            data_start += 32 - (data_start % 32)
    return tensors, data_start


def load_expert_proj(gguf: str, layer: int, expert: int, proj: str,
                     hidden: int, expert_dim: int):
    """Load one expert slice from stacked ffn_{proj}_exps.weight."""
    name = f"blk.{layer}.ffn_{proj}_exps.weight"
    tensors, data_start = load_gguf_meta(gguf)
    hit = None
    for t in tensors:
        if t[0] == name:
            hit = t
            break
    if not hit:
        raise SystemExit(f"missing {name}")
    dims, ttype, toff = hit[1], hit[2], hit[3]
    if ttype not in (GGML_Q4_K, GGML_Q6_K):
        raise SystemExit(f"{name} type={ttype} unsupported")
    if proj == "down":
        rows, cols = hidden, expert_dim
    else:
        rows, cols = expert_dim, hidden
    blocks_per_row = cols // QK_K
    bsz = Q4K_BLOCK if ttype == GGML_Q4_K else Q6K_BLOCK
    bytes_per_expert = rows * blocks_per_row * bsz
    with open(gguf, "rb") as f:
        f.seek(data_start + toff + expert * bytes_per_expert)
        raw = f.read(bytes_per_expert)
    if len(raw) != bytes_per_expert:
        raise SystemExit(f"short read {name} E{expert} got={len(raw)} want={bytes_per_expert}")
    print(f"LOADED {name} E{expert} type={ttype} rows={rows} cols={cols} "
          f"bytes={bytes_per_expert} dims={dims}")
    return raw, rows, cols, ttype


def compare(pred: List[float], got: List[float], tag: str) -> Tuple[float, int, int]:
    max_abs = 0.0
    max_ulp = 0
    first = -1
    for i, (a, b) in enumerate(zip(pred, got)):
        d = abs(a - b)
        u = ulp_diff(a, b)
        if d > max_abs:
            max_abs = d
        if u > max_ulp:
            max_ulp = u
        if first < 0 and (d > 0 or u > 0):
            first = i
    print(f"{tag} n={len(got)} maxAbs={max_abs:.9e} maxULP={max_ulp} firstDiffIdx={first}")
    if max_abs == 0.0 and max_ulp == 0:
        print(f"{tag}_VS_ORACLE=BITEXACT")
    elif max_ulp <= 2:
        print(f"{tag}_VS_ORACLE=ULP_OK")
    else:
        print(f"{tag}_VS_ORACLE=MISMATCH")
    return max_abs, max_ulp, first


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump-dir", required=True)
    ap.add_argument("--gguf", required=True)
    ap.add_argument("--layer", type=int, default=3)
    ap.add_argument("--expert", type=int, required=True)
    ap.add_argument("--hidden", type=int, default=2048)
    ap.add_argument("--expert-dim", type=int, default=512)
    args = ap.parse_args()

    L, E = args.layer, args.expert
    inp_p = find_bin(args.dump_dir, f"MOE_IN_L{L}_E{E}")
    gate_p = find_bin(args.dump_dir, f"MOE_GATE_L{L}_E{E}")
    up_p = find_bin(args.dump_dir, f"MOE_UP_L{L}_E{E}")
    down_p = find_bin(args.dump_dir, f"MOE_DOWN_L{L}_E{E}")
    print(f"PACKED_GEMV_ORACLE layer={L} expert={E}")
    print(f"inp={inp_p}\ngate={gate_p}\nup={up_p}\ndown={down_p}")
    if not inp_p or not gate_p or not up_p or not down_p:
        print("PACKED_GEMV_ORACLE=MISSING_DUMPS")
        return 2

    x = read_f32(inp_p)
    gate_d = read_f32(gate_p)
    up_d = read_f32(up_p)
    down_d = read_f32(down_p)
    if len(x) != args.hidden:
        print(f"DIM_MISMATCH inp={len(x)} hidden={args.hidden}")
        return 3

    gw, gr, gc, gt = load_expert_proj(args.gguf, L, E, "gate", args.hidden, args.expert_dim)
    uw, ur, uc, ut = load_expert_proj(args.gguf, L, E, "up", args.hidden, args.expert_dim)
    dw, dr, dc, dt = load_expert_proj(args.gguf, L, E, "down", args.hidden, args.expert_dim)

    gate_p_ = gemv_dispatch(gw, x, gr, gc, gt)
    up_p_ = gemv_dispatch(uw, x, ur, uc, ut)
    act = swiglu(gate_p_, up_p_)
    down_p_ = gemv_dispatch(dw, act, dr, dc, dt)

    g_abs, g_ulp, _ = compare(gate_p_, gate_d, "MOE_GATE")
    u_abs, u_ulp, _ = compare(up_p_, up_d, "MOE_UP")
    d_abs, d_ulp, _ = compare(down_p_, down_d, "MOE_DOWN")
    worst_ulp = max(g_ulp, u_ulp, d_ulp)
    worst_abs = max(g_abs, u_abs, d_abs)
    print(f"PACKED_GEMV_WORST maxAbs={worst_abs:.9e} maxULP={worst_ulp}")
    if worst_ulp <= 2:
        print("PACKED_GEMV_VS_ORACLE=ULP_OK")
    else:
        print("PACKED_GEMV_VS_ORACLE=MISMATCH")
    print("ORACLE_TYPE=INDEPENDENT_CPU_Q4K_Q8K_PLUS_Q6K_Q8K")
    print("PROMOTE=0 NOTE=local_oracle_not_llama_ref")
    return 0


if __name__ == "__main__":
    sys.exit(main())
