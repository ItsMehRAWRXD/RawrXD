#!/usr/bin/env python3
"""Quantized dot-product kernel parity for one real op.

The MLA B projection (kv_latent -> [k_nope | v] per head) is a single large
quantized matmul whose reference output llama.cpp dumps itself (probe_stepXX_
kv_up_lXX.bin) and whose native output the differential recorder captured
(MLA_up_projected_*). Comparing the two isolates the kernel from everything
else, and lets the two accumulation orders be scored against a real reference.
"""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1_current"
PHYS = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\genie_out\model.physical.txt"
GGUF = r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"


def read_record(path):
    b = open(path, "rb").read()
    op_id, layer, pos, ndim = struct.unpack_from("<IIQI", b, 0)
    shape = list(struct.unpack_from("<%dq" % ndim, b, 20))
    off = 20 + 8 * ndim + 8
    return shape, np.frombuffer(b[off:], dtype=np.float32).astype(np.float64)


def rec(label):
    tags = ("_l%d_" % LAYER, "_l%02d_" % LAYER)
    for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
        if label not in p or ("_p%d_" % STEP) not in p:
            continue
        if not any(t in p for t in tags):
            continue
        return read_record(p)
    return None


def read_llama(name):
    raw = open(os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (STEP, name, LAYER)), "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    return list(ne), np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


def tensors():
    out = {}
    for line in open(PHYS, encoding="utf-8", errors="replace"):
        if line.startswith("tensor\t") or "\t" not in line:
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 5:
            continue
        name, ttype, dims, nbytes, off = parts[:5]
        out[name] = (ttype, eval(dims), int(nbytes), int(off))
    return out


nev, kvup = read_llama("kv_up")
ours = rec("MLA_up_projected_l%d_p%d" % (LAYER, STEP))
print("llama kv_up  ne=%s size=%d" % (nev, kvup.size))
if ours is None:
    print("no native MLA_up_projected recorded for layer %d step %d" % (LAYER, STEP))
    sys.exit(1)
shape, native = ours
print("native up_projected shape=%s size=%d" % (shape, native.size))

n = min(kvup.size, native.size)
if n != kvup.size or n != native.size:
    print("size mismatch, comparing first %d" % n)

# llama dump layout: [heads * (noRope+value)] for one position
ref = kvup.reshape(-1) if kvup.size % 16 == 0 else kvup
nat = native.reshape(-1)
print("\nnative vs llama kv_up: cos=%.8f max|d|=%.8f rms=%.8f"
      % (cos(nat[:n], ref[:n]), float(np.abs(nat[:n] - ref[:n]).max()),
         float(np.sqrt(((nat[:n] - ref[:n]) ** 2).mean()))))

# Per-head comparison (the projection is head-major [16][256])
if n % 16 == 0:
    nh = n // 256 if 256 * 16 <= n else 16
    print("\nper-head (128-value groups):")
    worst = []
    for g in range(0, min(n, 4096), 256):
        a = nat[g:g + 256]
        b = ref[g:g + 256]
        worst.append((float(np.abs(a - b).max()), g // 256, cos(a, b)))
    worst.sort(reverse=True)
    for w, idx, c in worst[:6]:
        print("  head %2d: max|d|=%.6f cos=%.8f" % (idx, w, c))
