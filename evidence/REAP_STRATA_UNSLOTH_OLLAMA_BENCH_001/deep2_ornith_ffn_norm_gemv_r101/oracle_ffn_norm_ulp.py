#!/usr/bin/env python3
"""Local FFN_NORM oracle: RMSNorm(FFN_INP, weight, eps) vs dumped FFN_NORM.
Not llama.cpp. SOURCE_WIRED oracle only. PROMOTE=0.
"""
from __future__ import annotations

import argparse
import glob
import math
import os
import struct
import sys


def read_f32(path: str) -> list[float]:
    with open(path, "rb") as f:
        b = f.read()
    n = len(b) // 4
    return list(struct.unpack(f"<{n}f", b[: n * 4]))


def ulp_diff(a: float, b: float) -> int:
    if not math.isfinite(a) or not math.isfinite(b):
        return 2**31 - 1
    ai = struct.unpack("<I", struct.pack("<f", a))[0]
    bi = struct.unpack("<I", struct.pack("<f", b))[0]
    # map negatives to ordered two's complement space
    if ai & 0x80000000:
        ai = 0x80000000 - (ai & 0x7FFFFFFF)
    if bi & 0x80000000:
        bi = 0x80000000 - (bi & 0x7FFFFFFF)
    return abs(ai - bi)


def rmsnorm(x: list[float], w: list[float], eps: float) -> list[float]:
    n = len(x)
    ss = sum(v * v for v in x) / float(n)
    inv = 1.0 / math.sqrt(ss + eps)
    return [w[i] * (x[i] * inv) for i in range(n)]


def find_bin(dump_dir: str, key: str) -> str | None:
    pats = [
        os.path.join(dump_dir, f"deep2_{key}_*.bin"),
        os.path.join(dump_dir, f"*{key}*.bin"),
    ]
    hits: list[str] = []
    for p in pats:
        hits.extend(glob.glob(p))
    hits = sorted(set(hits))
    return hits[0] if hits else None


def load_ffn_norm_weight(gguf: str, layer: int) -> tuple[list[float], float]:
    """Minimal GGUF scan for blk.L.ffn_norm.weight (F32) + rms eps KV."""
    # qwen35moe/Ornith: post_attention_norm == FFN pre-norm; dense llama uses ffn_norm.
    cand_names = [
        f"blk.{layer}.post_attention_norm.weight".encode(),
        f"blk.{layer}.ffn_norm.weight".encode(),
    ]
    eps = 1e-6
    with open(gguf, "rb") as f:
        magic = f.read(4)
        if magic != b"GGUF":
            raise SystemExit("not GGUF")
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
                raise SystemExit(f"unsupported kv type {t}")

        for _ in range(n_kv):
            key = read_str().decode("utf-8", "replace")
            (vt,) = struct.unpack("<I", f.read(4))
            if "rms_norm_eps" in key or key.endswith("layer_norm_rms_epsilon"):
                if vt == 6:
                    (eps,) = struct.unpack("<f", f.read(4))
                elif vt == 12:
                    (eps,) = struct.unpack("<d", f.read(8))
                    eps = float(eps)
                else:
                    skip_val(vt)
            else:
                skip_val(vt)

        tensors = []
        for _ in range(n_tensors):
            tname = read_str()
            (ndims,) = struct.unpack("<I", f.read(4))
            dims = struct.unpack(f"<{ndims}Q", f.read(8 * ndims))
            (ttype,) = struct.unpack("<I", f.read(4))
            (toff,) = struct.unpack("<Q", f.read(8))
            tensors.append((tname, dims, ttype, toff))

        # data section starts after alignment from current; use file data offset
        # Prefer absolute: many GGUFs pad to 32 from end of tensor info.
        data_start = f.tell()
        align = 32
        if data_start % align:
            data_start += align - (data_start % align)

        for want in cand_names:
            for tname, dims, ttype, toff in tensors:
                if tname != want:
                    continue
                if ttype != 0:  # F32
                    raise SystemExit(f"norm type={ttype} want F32 name={want!r}")
                n = 1
                for d in dims:
                    n *= d
                f.seek(data_start + toff)
                raw = f.read(n * 4)
                w = list(struct.unpack(f"<{n}f", raw))
                print(f"NORM_WEIGHT_TENSOR={want.decode()} n={n}")
                return w, eps
    raise SystemExit(f"tensor none of {[c.decode() for c in cand_names]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump-dir", required=True)
    ap.add_argument("--gguf", required=True)
    ap.add_argument("--layer", type=int, default=0)
    ap.add_argument("--eps", type=float, default=None)
    args = ap.parse_args()

    inp_p = find_bin(args.dump_dir, f"FFN_INP_{args.layer}")
    out_p = find_bin(args.dump_dir, f"FFN_NORM_{args.layer}")
    if not inp_p or not out_p:
        print(f"FFN_NORM_ORACLE=MISSING inp={inp_p} out={out_p}")
        return 2

    x = read_f32(inp_p)
    y = read_f32(out_p)
    w, eps_kv = load_ffn_norm_weight(args.gguf, args.layer)
    eps = args.eps if args.eps is not None else eps_kv
    if len(x) != len(y) or len(x) != len(w):
        print(f"FFN_NORM_ORACLE=DIM_MISMATCH n_x={len(x)} n_y={len(y)} n_w={len(w)}")
        return 3

    pred = rmsnorm(x, w, eps)
    max_abs = 0.0
    max_ulp = 0
    first = -1
    for i in range(len(y)):
        d = abs(pred[i] - y[i])
        u = ulp_diff(pred[i], y[i])
        if d > max_abs:
            max_abs = d
        if u > max_ulp:
            max_ulp = u
        if first < 0 and (d > 0 or u > 0):
            first = i

    print(f"FFN_NORM_ORACLE=COMPARED layer={args.layer}")
    print(f"inp={inp_p}")
    print(f"out={out_p}")
    print(f"n={len(y)} eps={eps:.9e}")
    print(f"maxAbs={max_abs:.9e} maxULP={max_ulp} firstDiffIdx={first}")
    if max_abs == 0.0 and max_ulp == 0:
        print("FFN_NORM_VS_ORACLE=BITEXACT")
    elif max_ulp <= 2:
        print("FFN_NORM_VS_ORACLE=ULP_OK")
    else:
        print("FFN_NORM_VS_ORACLE=MISMATCH")
    print("PROMOTE=0 NOTE=local_oracle_not_llama_ref")
    return 0


if __name__ == "__main__":
    sys.exit(main())
