import os
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"


def load(p):
    return np.fromfile(p, dtype=np.float32)


def pick(d, key, side):
    hits = sorted(
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith(".bin") and f"{side}_{key}_" in n
    )
    return hits[0] if hits else None


r = os.path.join(ev, "stage_dump_attn_pre_o_0_pos1_fa40e_r85b")
c = os.path.join(ev, "stage_dump_attn_pre_o_0_pos1_c740")
for k in [
    "ATTN_NORM_0_pos0",
    "FFN_INP_0_pos0",
    "FFN_NORM_0_pos0",
    "FFN_DOWN_0_pos0",
    "ATTN_NORM_1_pos0",
    "FFN_INP_1_pos0",
    "FFN_NORM_1_pos0",
]:
    a, b = load(pick(r, k, "deep2")), load(pick(c, k, "deep2"))
    d = np.abs(a - b)
    print(f"{k}: maxAbs={float(d.max()):.6e} bitexact={float(d.max())==0.0}")

inp = load(pick(r, "FFN_INP_1_pos0", "deep2"))
nr = load(pick(r, "FFN_NORM_1_pos0", "deep2"))
nc = load(pick(c, "FFN_NORM_1_pos0", "deep2"))
ref = load(pick(os.path.join(ev, "stage_dump_gpu_ref"), "FFN_NORM_1_pos0", "llama"))
eps = 1e-5
dim = 2048
sumSq_d = float(np.sum(inp.astype(np.float64) ** 2) / dim)
sumSq_f = float(np.sum((inp * inp).astype(np.float32)) / np.float32(dim))
print("meanSq double", sumSq_d, "float32-accum", sumSq_f)
print("norm r vs ref", float(np.max(np.abs(nr - ref))))
print("norm c vs ref", float(np.max(np.abs(nc - ref))))
print("norm r vs c", float(np.max(np.abs(nr - nc))))
# infer weight*inv from nc/inp where inp!=0
mask = np.abs(inp) > 1e-6
scale_r = np.zeros_like(inp)
scale_c = np.zeros_like(inp)
scale_r[mask] = nr[mask] / inp[mask]
scale_c[mask] = nc[mask] / inp[mask]
print(
    "scale r vs c maxAbs",
    float(np.max(np.abs(scale_r[mask] - scale_c[mask]))),
    "mean r",
    float(np.mean(scale_r[mask])),
    "mean c",
    float(np.mean(scale_c[mask])),
)
