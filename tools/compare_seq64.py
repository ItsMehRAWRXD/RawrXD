#!/usr/bin/env python3
"""Native 64/65-position teacher-forced differential against the reproducible
reference (evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/ref_64)."""
import os
import sys

import numpy as np

EV = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001"
REF = r"F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_64"
native = sys.argv[1] if len(sys.argv) > 1 else os.path.join(EV, "native_tf_seq64")

ok = bad = 0
rows = []
pos = 0
while True:
    pn = os.path.join(native, "native_tf_logits_pos%d.bin" % pos)
    rp = os.path.join(REF, "ref_logits_pos%d.bin" % pos)
    if not (os.path.isfile(pn) and os.path.isfile(rp)):
        break
    a = np.fromfile(pn, dtype=np.float32).astype(np.float64)
    b = np.fromfile(rp, dtype=np.float32).astype(np.float64)
    n = min(a.size, b.size)
    a, b = a[:n], b[:n]
    d = a - b
    cos = float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b)))
    aa, ra = int(a.argmax()), int(b.argmax())
    m = aa == ra
    ok += 1 if m else 0
    bad += 0 if m else 1
    rows.append((pos, aa, ra, m, cos, float(np.sqrt((d * d).mean())),
                 float(np.abs(d).max())))
    pos += 1

print("pos  native ref  match  cosine       rmse      max|d|")
for pos, aa, ra, m, cos, rmse, mx in rows:
    print("%3d  %6d %4d  %-5s  %11.8f  %8.5f  %8.5f"
          % (pos, aa, ra, "YES" if m else "NO", cos, rmse, mx))
n = max(1, len(rows))
print("\nPOSITIONS=%d  ARGMAX_MATCH=%d/%d  mean_cos=%.8f  min_cos=%.8f  max_rmse=%.6f"
      % (len(rows), ok, ok + bad, sum(r[4] for r in rows) / n,
         min(r[4] for r in rows), max(r[5] for r in rows)))
print("ALL_POSITIONS_MATCH=%s" % ("YES" if bad == 0 and rows else "NO"))
misses = [r[0] for r in rows if not r[3]]
if misses:
    print("argmax-mismatch positions: %s" % misses)
