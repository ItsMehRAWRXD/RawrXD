# compare_ab.py -- A/B the unified K-quant dot against the previous DeepSeek
# baseline (float-dot MoE path) and real llama.cpp.
import os
import numpy as np

BASE = r"F:\rawrxd\evidence\PARITY_2026-10-13\postbiasfix"
REF = os.path.join(BASE, "ds_llama67", "ref_logits_pos%d.bin")


def load(path):
    return np.fromfile(path, dtype="<f4").astype(np.float64)


print("VARIANT vs real llama.cpp (DeepSeek-V2-Lite, 67 teacher-forced positions)")
print(f"{'variant':<26}{'argmax':>10}{'wrst_cos':>11}{'wrst_relL2':>13}"
      f"{'mean_relL2':>12}{'wrst_rmse':>11}")

variants = [
    ("float-dot MoE (pre-fix)", "ds_d2_67"),
    ("unified int-MAC (post) ", "ds_d2_67_v2"),
]
for tag, sub in variants:
    res = []
    for p in range(67):
        L = load(REF % p)
        D = load(os.path.join(BASE, f"{sub}.pos{p}.f32"))
        n = min(L.size, D.size)
        L, D = L[:n], D[:n]
        d = D - L
        res.append((int(np.argmax(D)) == int(np.argmax(L)),
                    float(D @ L / (np.linalg.norm(D) * np.linalg.norm(L))),
                    float(np.linalg.norm(d) / np.linalg.norm(L)),
                    float(np.sqrt(np.mean(d * d)))))
    m = sum(1 for r in res if r[0])
    print(f"{tag:<26}{m:>8}/67{min(r[1] for r in res):>11.6f}"
          f"{max(r[2] for r in res):>13.6f}{np.mean([r[2] for r in res]):>12.6f}"
          f"{max(r[3] for r in res):>11.6f}")
