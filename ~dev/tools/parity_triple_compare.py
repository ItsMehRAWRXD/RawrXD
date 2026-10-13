# parity_triple_compare.py -- decisive three-way logit parity at every
# teacher-forced position:
#   llama.cpp (authoritative, real generator)  vs
#   numpy reference (bias-aware)               vs
#   Deep2 engine under test
#
# Reports cosine, RMSE, max-abs, argmax agreement, and the first divergence.
import os
import numpy as np

BASE = r"F:\rawrxd\evidence\PARITY_2026-10-13"
LLAMA = os.path.join(BASE, "llama_truth")
REF = "reftied750"
D2 = "qwen_d2_750"
NTOK = 7


def load(path):
    if not os.path.exists(path):
        return None
    return np.fromfile(path, dtype="<f4")


def stats(a, b):
    a64 = a.astype(np.float64)
    b64 = b.astype(np.float64)
    d = a64 - b64
    cos = float(a64 @ b64 / (np.linalg.norm(a64) * np.linalg.norm(b64)))
    rmse = float(np.sqrt(np.mean(d * d)))
    mx = float(np.abs(d).max())
    na = int(np.argmax(a))
    nb = int(np.argmax(b))
    rel = float(np.linalg.norm(d) / max(np.linalg.norm(b64), 1e-30))
    return cos, rmse, mx, rel, na, nb


print(f"{'pos':>3} {'pair':<28} {'finite':>7} {'cosine':>12} {'rmse':>10} "
      f"{'maxabs':>11} {'relL2':>10}  argmax")
print("-" * 104)

first_div = None
for pos in range(NTOK):
    lf = os.path.join(LLAMA, f"ref_logits_pos{pos}.bin")
    rf = os.path.join(BASE, f"{REF}.pos{pos}.LOGITS.f32")
    df = os.path.join(BASE, f"{D2}.pos{pos}.f32")
    L, R, D = load(lf), load(rf), load(df)
    if L is None:
        print(f"{pos:>3} llama ref MISSING")
        continue
    print(f"{pos:>3} llama ref: n={L.size} bytes={os.path.getsize(lf)} "
          f"finite={int(np.isfinite(L).sum())} argmax={int(np.argmax(L))}")
    for tag, X in (("  ref(bias) vs llama", R), ("  deep2      vs llama", D)):
        if X is None or X.size != L.size:
            print(f"{tag:>3} {tag} size-mismatch/absent")
            continue
        cos, rmse, mx, rel, na, nb = stats(X, L)
        flag = "OK " if na == nb else "DIVERGE"
        print(f"{pos:>3} {tag:24s} {int(np.isfinite(X).sum()):>6} "
              f"{cos:12.6f} {rmse:10.4g} {mx:11.4g} {rel:10.4g}  "
              f"{na} vs {nb}  {flag}")
        if tag.startswith("  deep2") and na != nb and first_div is None:
            first_div = (pos, cos, rmse, mx, na, nb)
    print("-" * 104)

if first_div:
    print(f"FIRST_DIVERGENT_POSITION={first_div[0]} deep2_argmax={first_div[4]} "
          f"llama_argmax={first_div[5]} cosine={first_div[1]:.6f} "
          f"rmse={first_div[2]:.6g} maxabs={first_div[3]:.6g}")
else:
    print("FIRST_DIVERGENT_POSITION=none (Deep2 argmax matches llama.cpp)")
