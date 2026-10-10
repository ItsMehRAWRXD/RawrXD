#!/usr/bin/env python3
"""Position-1 logit margin: is the argmax disagreement a near-tie inside the
residual numerical error, or a real divergence?

Also reports where the native/ref error budget sits against the llama.cpp
quantization floor (the difference between two independent llama.cpp runs with
different matmul blocking is the smallest achievable error for this model).
"""
import os

import numpy as np

EV = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001"
REF = r"F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_teacher_forced"


def load(d, pos):
    return np.fromfile(os.path.join(d, "ref_logits_pos%d.bin" % pos),
                       dtype=np.float32).astype(np.float64)


def top(x, k=5):
    idx = np.argsort(-x)[:k]
    return [(int(i), float(x[i])) for i in idx]


for pos in range(0, 4):
    nat = np.fromfile(os.path.join(EV, "native_tf_logits_pos%d.bin" % pos),
                      dtype=np.float32).astype(np.float64)
    ref = load(REF, pos)
    nm, rmi = int(nat.argmax()), int(ref.argmax())
    d = np.abs(nat - ref)
    print("pos %d: argmax native=%d ref=%d  top5 native=%s" % (pos, nm, rmi, top(nat)))
    print("        top5 ref   =%s" % (top(ref),))
    print("        margin ref[%d]-ref[%d] = %.6f   margin native[%d]-native[%d] = %.6f"
          % (rmi, np.argsort(-ref)[1], ref[rmi] - np.sort(ref)[-2],
             nm, np.argsort(-nat)[1], nat[nm] - np.sort(nat)[-2]))
    print("        rmse=%.6f  max|d|=%.6f  p99.9|d|=%.6f  mean|d|=%.6f\n"
          % (np.sqrt(((nat - ref) ** 2).mean()), d.max(),
             np.quantile(d, 0.999), d.mean()))
