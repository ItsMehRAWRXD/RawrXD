# Quick FFN_DOWN_2 + PRE_O_1 hold check. PROMOTE=0
import os, re, sys
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
ABS = 1e-6


def load(p):
    return np.fromfile(p, dtype=np.float32)


def pick(d, key, prefer_n=None):
    hits = []
    for n in os.listdir(d):
        if not n.endswith(".bin"):
            continue
        if key not in n:
            continue
        if re.search(r"_pos1\d_", n):
            continue
        hits.append(os.path.join(d, n))
    if prefer_n is not None:
        pref = [p for p in hits if f"_n{prefer_n}_" in os.path.basename(p)]
        if pref:
            hits = pref
    hits = sorted(hits)
    return hits[-1] if hits else None


def mx(a, b):
    n = min(len(a), len(b))
    m = 0.0
    idx = -1
    for i in range(n):
        ae = abs(float(a[i] - b[i]))
        if ae > m:
            m, idx = ae, i
    return m, idx


gpu = sys.argv[1]
ref = os.path.join(ev, "stage_dump_ref_matched")
print("GPU", gpu)
for k, pn in [
    ("ATTN_PRE_O_0_pos1", 2048),
    ("ATTN_PRE_O_1_pos1", 2048),
    ("Q_PRE_ROPE_1_pos1", 2048),
    ("FFN_DOWN_2_pos1", 2048),
]:
    gp = pick(gpu, f"deep2_{k}", pn)
    rp = pick(ref, f"llama_{k}", pn)
    if k.startswith("FFN_DOWN_2") and (not rp):
        rp = pick(os.path.join(ev, "stage_dump_gpu_ref"), f"llama_{k}", pn)
    if not gp or not rp:
        print(k, "MISSING", bool(gp), bool(rp))
        continue
    g, r = load(gp), load(rp)
    m, idx = mx(g, r)
    print(f"{k}: maxAbs={m:.6e} @idx{idx} UNDER={int(m <= ABS)}")
    if "Q_PRE" in k and len(g) > 747:
        print(f"  @747 gpu={float(g[747]):.10e} ref={float(r[747]):.10e}")
