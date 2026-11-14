import glob, os
import numpy as np

os.chdir(r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001")


def load(p):
    return np.fromfile(p, dtype=np.float32)


def mx(a, b):
    n = min(len(a), len(b))
    d = np.abs(a[:n] - b[:n])
    i = int(np.argmax(d))
    return float(d[i]), i, float(a[i]), float(b[i])


def find(d, pat):
    g = sorted(glob.glob(os.path.join(d, pat)))
    return g[0] if g else None


def ulps(a, b):
    a = np.float32(a)
    b = np.float32(b)
    if a == b:
        return 0.0
    ai = int(np.asarray(a).view(np.int32))
    bi = int(np.asarray(b).view(np.int32))
    if (ai ^ bi) < 0:
        return float(abs(ai) + abs(bi))
    return float(abs(ai - bi))


gpu_dirs = [
    "stage_dump_ffn_down_2_hostq4",
    "stage_dump_ffn_down_2_q6spv",
    "stage_dump_attn_out14_oproj",
    "stage_dump_layer2_plus_spv4548",
]
ref_dirs = [
    "stage_dump_gpu_ref",
    "stage_dump_ffn_act2_c740_after_ref",
]

refd = None
refa = None
for d in ref_dirs:
    if refd is None:
        refd = find(d, "llama_FFN_DOWN_2_pos0*.bin")
    if refa is None:
        refa = find(d, "llama_FFN_ACT_2_pos0*.bin")
print("refd", refd)
print("refa", refa)
r = load(refd)
ra = load(refa)

# Prefer seq289-sized matched refs when multiple
if "seq289" not in os.path.basename(refd):
    cands = sorted(glob.glob(os.path.join(os.path.dirname(refd), "llama_FFN_DOWN_2_pos0*seq289*.bin")))
    if cands:
        refd = cands[0]
        r = load(refd)
        print("refd prefer", refd)

keys = [
    ("FFN_ACT_2", "deep2_FFN_ACT_2_pos0*.bin", "llama_FFN_ACT_2", ra, 1e-5),
    ("FFN_DOWN_2", "deep2_FFN_DOWN_2_pos0*.bin", "llama_FFN_DOWN_2", r, 1e-5),
    ("ATTN_PRE_O_14", "deep2_ATTN_PRE_O_14_pos0*.bin", "llama_ATTN_PRE_O_14", None, 1e-4),
    ("ATTN_OUT_14", "deep2_ATTN_OUT_14_pos0*.bin", "llama_ATTN_OUT_14", None, 1e-4),
    ("FINAL_NORM", "deep2_REF_FINAL_HIDDEN_pos0*.bin", "llama_REF_FINAL_HIDDEN", None, 1e-4),
]

# also load PRE/OUT/FINAL refs from stage dirs
pre_ref = find("stage_dump_gpu_ref", "llama_ATTN_PRE_O_14_pos0*.bin")
out_ref = find("_cmp_attn_out14_stage", "llama_ATTN_OUT_14.bin")
if out_ref is None:
    out_ref = find("stage_dump_gpu_ref", "llama_ATTN_OUT_14_pos0*.bin")
fin_ref = find("_cmp_attn_out14_stage", "llama_REF_FINAL_HIDDEN_pos0.bin")
if fin_ref is None:
    fin_ref = find("stage_dump_gpu_ref", "llama_REF_FINAL_HIDDEN_pos0*.bin")
print("pre_ref", pre_ref)
print("out_ref", out_ref)
print("fin_ref", fin_ref)

for gd in gpu_dirs:
    if not os.path.isdir(gd):
        print(f"\n[{gd}] MISSING")
        continue
    print(f"\n[{gd}]")
    for name, pat, rname, rarr, tol in keys:
        gp = find(gd, pat)
        if gp is None:
            # FINAL often named differently
            if name == "FINAL_NORM":
                gp = find(gd, "deep2_*FINAL*pos0*.bin") or find(gd, "*FINAL_NORM*pos0*.bin")
            if name == "ATTN_OUT_14":
                gp = find(gd, "deep2_ATTN_OUT_14*.bin")
            if name == "ATTN_PRE_O_14":
                gp = find(gd, "deep2_ATTN_PRE_O_14*.bin")
        if gp is None:
            print(f"  {name}: NO_GPU")
            continue
        if name == "FFN_ACT_2":
            rr = ra
        elif name == "FFN_DOWN_2":
            rr = r
        elif name == "ATTN_PRE_O_14":
            if pre_ref is None:
                print(f"  {name}: NO_REF")
                continue
            rr = load(pre_ref)
        elif name == "ATTN_OUT_14":
            if out_ref is None:
                print(f"  {name}: NO_REF")
                continue
            rr = load(out_ref)
        else:
            if fin_ref is None:
                print(f"  {name}: NO_REF")
                continue
            rr = load(fin_ref)
        g = load(gp)
        m, i, gv, rv = mx(g, rr)
        n_gt = int(np.sum(np.abs(g[: len(rr)] - rr[: len(g)]) > tol))
        print(
            f"  {name}: maxAbs={m:.6e} @idx{i} n_gt={n_gt}/{min(len(g),len(rr))} "
            f"UNDER_TOL={'Y' if m <= tol else 'N'} ulps={ulps(gv, rv):.1f} "
            f"gpu={os.path.basename(gp)}"
        )
