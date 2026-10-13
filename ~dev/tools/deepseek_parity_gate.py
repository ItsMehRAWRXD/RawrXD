# deepseek_parity_gate.py -- DeepSeek-V2-Lite 67-position parity gate:
# real llama.cpp (teacher-forced dump tool) vs post-bias-fix Deep2 (CPU).
import os
import numpy as np

REF = (r"F:\rawrxd\evidence\PARITY_2026-10-13\postbiasfix\ds_llama67"
       r"\ref_logits_pos%d.bin")
D2 = r"F:\rawrxd\evidence\PARITY_2026-10-13\postbiasfix\ds_d2_67.pos%d.f32"
NPOS = 67

rows = []
for p in range(NPOS):
    L = np.fromfile(REF % p, dtype="<f4").astype(np.float64)
    D = np.fromfile(D2 % p, dtype="<f4").astype(np.float64)
    n = min(L.size, D.size)
    L, D = L[:n], D[:n]
    d = D - L
    cos = float(D @ L / (np.linalg.norm(D) * np.linalg.norm(L)))
    rmse = float(np.sqrt(np.mean(d * d)))
    mx = float(np.abs(d).max())
    rel = float(np.linalg.norm(d) / np.linalg.norm(L))
    rows.append((p, int(np.argmax(D)), int(np.argmax(L)), cos, rmse, mx, rel))

match = sum(1 for r in rows if r[1] == r[2])
print(f"POSITIONS={NPOS} LOGITS_PER_POSITION=102400")
print(f"ARGMAX_MATCHES={match}/{NPOS}   "
      f"WORST_COSINE={min(r[3] for r in rows):.6f}   "
      f"WORST_RMSE={max(r[4] for r in rows):.6f}   "
      f"WORST_MAXABS={max(r[5] for r in rows):.6f}   "
      f"WORST_RELL2={max(r[6] for r in rows):.6f}")
bad = [r for r in rows if r[1] != r[2]]
if bad:
    print("FIRST_ARGMAX_MISMATCH=" + str(bad[0][0]))
    for r in bad[:6]:
        p, a, b, cos, rmse, mx, rel = r
        print(f"  pos={p:>3} d2={a:>7} llama={b:>7} cos={cos:.6f} "
              f"rmse={rmse:.6g}")
else:
    print("FIRST_ARGMAX_MISMATCH=none")

# position 15 detail (the earlier reported mismatch)
for p in (15, 13):
    L = np.fromfile(REF % p, dtype="<f4").astype(np.float64)
    D = np.fromfile(D2 % p, dtype="<f4").astype(np.float64)
    idx = np.argsort(-L)[:5]
    print(f"\nPOS={p} reference top-5: " +
          ", ".join(f"{int(i)}:{L[i]:.6f}" for i in idx))
    print(f"POS={p} deep2 same ids : " +
          ", ".join(f"{int(i)}:{D[i]:.6f}" for i in idx))
    d2idx = np.argsort(-D)[:5]
    print(f"POS={p} deep2 top-5    : " +
          ", ".join(f"{int(i)}:{D[i]:.6f}" for i in d2idx))
