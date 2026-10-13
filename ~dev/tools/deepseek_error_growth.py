# deepseek_error_growth.py -- is the residual error position-dependent
# (attention / KV path) or constant from token 0 (projection / weights)?
import os
import numpy as np

REF = (r"F:\rawrxd\evidence\PARITY_2026-10-13\postbiasfix\ds_llama67"
       r"\ref_logits_pos%d.bin")
D2 = r"F:\rawrxd\evidence\PARITY_2026-10-13\postbiasfix\ds_d2_67.pos%d.f32"

rows = []
for p in range(67):
    L = np.fromfile(REF % p, dtype="<f4").astype(np.float64)
    D = np.fromfile(D2 % p, dtype="<f4").astype(np.float64)
    n = min(L.size, D.size)
    L, D = L[:n], D[:n]
    d = D - L
    rows.append((p, float(np.linalg.norm(d) / np.linalg.norm(L)),
                 float(D @ L / (np.linalg.norm(D) * np.linalg.norm(L))),
                 int(np.argmax(D)) == int(np.argmax(L))))

print("pos   relL2     cosine   argmax_match   bar")
for p, rel, cos, m in rows:
    print(f"{p:>3}  {rel:9.6f}  {cos:.6f}   {'YES' if m else 'no ':>11}   "
          f"{'#' * int(rel * 120)}")

early = [r for p, r, c, m in rows if p <= 3]
late = [r for p, r, c, m in rows if p >= 60]
print(f"\nmean relL2 positions 0-3    = {np.mean(early):.6f}")
print(f"mean relL2 positions 60-66  = {np.mean(late):.6f}")
print("VERDICT: " + (
    "error grows with position -> attention/KV/position-dependent path"
    if np.mean(late) > 1.6 * np.mean(early) else
    "error is roughly position-independent -> projection/protocol path"))
