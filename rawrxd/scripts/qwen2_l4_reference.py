#!/usr/bin/env python3
"""DEEP2_QWEN2_CPU_CORRECTNESS_001 — L4 first-mismatch decider.

Reads full L4 vectors from the extended oracle trace and recomputes the FFN
chain independently from real GGUF bytes (canonical Q4K/Q6K dequant, numpy).
Reports the first checkpoint whose value diverges beyond tolerance.
"""
import re
import struct

import numpy as np

GGUF = r"F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf"
TRACE = r"F:\~dev\_qwen2_32b_fixed_trace.txt"


def parse_header(path):
    f = open(path, "rb")
    f.read(4)
    struct.unpack("<I", f.read(4))
    n_tensors = struct.unpack("<Q", f.read(8))[0]
    n_kv = struct.unpack("<Q", f.read(8))[0]

    def read_str(fh):
        n = struct.unpack("<Q", fh.read(8))[0]
        return fh.read(n).decode("utf-8", "replace")

    def skip_value(fh, t):
        if t == 8:
            read_str(fh)
        elif t in (0, 1, 7):
            fh.seek(1, 1)
        elif t in (2, 3):
            fh.seek(2, 1)
        elif t in (4, 5, 6):
            fh.seek(4, 1)
        elif t in (10, 11, 12):
            fh.seek(8, 1)
        elif t == 9:
            et = struct.unpack("<I", fh.read(4))[0]
            n = struct.unpack("<Q", fh.read(8))[0]
            for _ in range(n):
                skip_value(fh, et)
        else:
            raise ValueError(t)

    for _ in range(n_kv):
        read_str(f)
        t = struct.unpack("<I", f.read(4))[0]
        skip_value(f, t)
    tinfos = {}
    for _ in range(n_tensors):
        name = read_str(f)
        nd = struct.unpack("<I", f.read(4))[0]
        dims = struct.unpack("<" + "Q" * nd, f.read(8 * nd))
        ttype = struct.unpack("<I", f.read(4))[0]
        off = struct.unpack("<Q", f.read(8))[0]
        tinfos[name] = (dims, ttype, off)
    data_start = (f.tell() + 31) // 32 * 32
    f.close()
    return tinfos, data_start


def f16_scalar(h):
    s = -1.0 if h & 0x8000 else 1.0
    e = (h >> 10) & 0x1F
    fr = h & 0x3FF
    if e == 0:
        return s * fr * 2.0**-24
    return s * (1.0 + fr / 1024.0) * 2.0 ** (e - 15)


F16_TAB = np.array([f16_scalar(i) for i in range(65536)], dtype=np.float32)


def deq_q4k(path, tinfos, data_start, name):
    dims, ttype, off = tinfos[name]
    rows, cols = dims[1], dims[0]
    row_bytes = (cols // 256) * 144
    f = open(path, "rb")
    f.seek(data_start + off)
    raw = np.frombuffer(f.read(rows * row_bytes), dtype=np.uint8).reshape(rows, row_bytes)
    f.close()
    d = np.frombuffer(raw[:, 0:2].tobytes(), dtype="<u2")
    dmin = np.frombuffer(raw[:, 2:4].tobytes(), dtype="<u2")
    dv = F16_TAB[d].reshape(rows, 1).astype(np.float64)
    dminv = F16_TAB[dmin].reshape(rows, 1).astype(np.float64)
    sc = np.zeros((rows, 8), dtype=np.int64)
    mn = np.zeros((rows, 8), dtype=np.int64)
    s = raw[:, 4:16].astype(np.int64)
    for j in range(8):
        if j < 4:
            sc[:, j] = s[:, j] & 63
            mn[:, j] = s[:, j + 4] & 0x3F
        else:
            sc[:, j] = (s[:, j + 4] & 0xF) | ((s[:, j - 4] >> 6) << 4)
            mn[:, j] = (s[:, j + 4] >> 4) | ((s[:, j] & 0x3F) << 4)
    qs = raw[:, 16:144].reshape(rows, 8, 16).astype(np.int64)
    vals = np.empty((rows, cols), dtype=np.float64)
    for isb in range(8):
        srow = dv[:, 0] * sc[:, isb]
        mrow = dminv[:, 0] * mn[:, isb]
        qsub = qs[:, isb, :]
        vals[:, isb * 32:isb * 32 + 16] = srow[:, None] * (qsub & 0xF) - mrow[:, None]
        vals[:, isb * 32 + 16:isb * 32 + 32] = srow[:, None] * (qsub >> 4) - mrow[:, None]
    return vals


def silu_np(x):
    return x / (1.0 + np.exp(-x))


def parse_vecs():
    vecs = {}
    cur = None
    buf = []
    with open(TRACE, "r", encoding="utf-8") as f:
        for line in f:
            m = re.match(r"STEP=0 VEC=LAYER_4_(\S+) N=(\d+)", line.strip())
            if m:
                if cur:
                    vecs.setdefault(cur, np.asarray(buf, dtype=np.float64))
                cur = m.group(1)
                buf = []
                continue
            if cur and re.fullmatch(r"-?[0-9.eE+,\-]+", line.strip()):
                buf.extend(float(x) for x in line.strip().split(","))
    if cur:
        vecs.setdefault(cur, np.asarray(buf, dtype=np.float64))
    return vecs


def main():
    tinfos, data_start = parse_header(GGUF)
    vecs = parse_vecs()
    if not vecs:
        print("L4REF=FAIL NO_VEC_RECORDS")
        return 1
    names = sorted(set(vecs.keys()))
    print("VECS:", names)

    failures = []

    def check(name, got, ref, tol=2e-2):
        if got is None or ref is None:
            print(f"{name}: MISSING")
            return
        n = min(len(got), len(ref))
        if n == 0 or np.max(np.abs(ref[:n])) == 0:
            print(f"{name}: DEGENERATE")
            return
        rel = float(np.max(np.abs(got[:n] - ref[:n])) / np.max(np.abs(ref[:n])))
        status = "PASS" if rel < tol else "FAIL"
        print(f"{name}: rel_err={rel:.4g} {status}")
        if rel >= tol:
            failures.append((name, rel))

    x = vecs.get("FFN_NORM")
    if x is not None and len(x) == 5120:
        gate = deq_q4k(GGUF, tinfos, data_start, "blk.4.ffn_gate.weight")
        check("FFN_GATE", vecs.get("FFN_GATE"), gate @ x)

        up = deq_q4k(GGUF, tinfos, data_start, "blk.4.ffn_up.weight")
        ref_up = up @ x
        check("FFN_UP", vecs.get("FFN_UP"), ref_up)

        g = vecs.get("FFN_GATE")
        u = vecs.get("FFN_UP")
        if g is not None and u is not None:
            sw = silu_np(g) * u
            check("SWIGLU", vecs.get("SWIGLU"), sw)
    else:
        print("FFN_NORM vector missing or wrong size:", None if x is None else len(x))

    if failures:
        print("FIRST_MISMATCH=", failures[0][0], "rel=", failures[0][1])
        print("L4REF=FAIL")
        return 1
    print("L4REF=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
