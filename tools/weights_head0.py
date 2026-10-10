#!/usr/bin/env python3
"""Read the runtime's RECORDED attention weights (llama has softmax; we record the
post-softmax vector) for head 0 and compare with llama.cpp's kq_soft_max."""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1b"

raw = open(os.path.join(D, "probe_step%02d_kq_soft_max_l%02d.bin" % (STEP, LAYER)), "rb").read()
ne = struct.unpack("<4q", raw[4:36])
Soft = np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64).reshape(ne[2], ne[0], ne[1])
n_kv = STEP + 1
llama_w = [float(Soft[0, kv][0]) for kv in range(n_kv)]

tags = ("_l%d_" % LAYER, "_l%02d_" % LAYER)
found = None
for p in sorted(glob.glob(os.path.join(ND, "rec_*"))):
    if "Attention_Weights" not in p or ("_p%d_" % STEP) not in p:
        continue
    if not any(t in p for t in tags):
        continue
    b = open(p, "rb").read()
    cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
    found = (os.path.basename(p),
             np.frombuffer(b[20 + 8 + 8:20 + 8 + 8 + cnt * 4], dtype=np.float32).astype(np.float64))
    break

print("layer %d step %d" % (LAYER, STEP))
print("  llama  h0 weights: %s" % np.round(llama_w, 6).tolist())
if found:
    print("  ours   file: %s" % found[0])
    print("  ours   weights: %s" % np.round(found[1], 6).tolist())
    if found[1].size == n_kv:
        d = np.abs(np.array(llama_w) - found[1])
        print("  max|d| = %.6f" % float(d.max()))
else:
    print("  no recorded weights file found")
