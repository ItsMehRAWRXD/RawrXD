#!/usr/bin/env python3
"""Compare a native teacher-forced logits directory against the reproducible
llama.cpp reference, position by position."""
import os
import sys

import numpy as np

VAL = 102400
EV = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001"
REF = r"F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_teacher_forced"


def load(path):
    raw = open(path, "rb").read()
    if len(raw) != VAL * 4:
        raise ValueError("%s: %d bytes != %d" % (path, len(raw), VAL * 4))
    return np.frombuffer(raw, dtype=np.float32).astype(np.float64)


native_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(EV, "native_tf_current")
ref_dir = sys.argv[2] if len(sys.argv) > 2 else REF

ok = 0
bad = 0
rows = []
pos = 0
while True:
    np_path = os.path.join(native_dir, "native_tf_logits_pos%d.bin" % pos)
    rp = os.path.join(ref_dir, "ref_logits_pos%d.bin" % pos)
    if not (os.path.isfile(np_path) and os.path.isfile(rp)):
        break
    n = load(np_path)
    r = load(rp)
    d = n - r
    cos = float(n @ r / (np.linalg.norm(n) * np.linalg.norm(r)))
    n_arg, r_arg = int(n.argmax()), int(r.argmax())
    match = n_arg == r_arg
    ok += 1 if match else 0
    bad += 0 if match else 1
    rows.append((pos, n_arg, r_arg, match, cos,
                 float(np.sqrt((d * d).mean())), float(np.abs(d).max())))
    pos += 1

print("pos  native_arg ref_arg  match  cosine        rmse       max|d|")
for pos, n_arg, r_arg, match, cos, rmse, mx in rows:
    print("%3d  %10d %6d  %-5s  %12.8f  %8.5f  %8.5f"
          % (pos, n_arg, r_arg, "YES" if match else "NO", cos, rmse, mx))
n = max(1, len(rows))
print("\nARGMAX_MATCH=%d/%d  mean_cos=%.8f  min_cos=%.8f  max_rmse=%.6f"
      % (ok, ok + bad, sum(r[4] for r in rows) / n,
         min(r[4] for r in rows), max(r[5] for r in rows)))
print("ALL_POSITIONS_MATCH=%s" % ("YES" if bad == 0 and rows else "NO"))
