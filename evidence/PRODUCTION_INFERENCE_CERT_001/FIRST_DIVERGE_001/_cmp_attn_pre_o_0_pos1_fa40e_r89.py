"""R89 FA+pairwise F32 RMSNorm+SPV40E compare. CROSS_SHA_CREDIT=0. PROMOTE=0."""
import os, hashlib
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_0_pos1_fa40e_r89")
ref = os.path.join(ev, "stage_dump_ref_matched")
c740 = os.path.join(ev, "stage_dump_attn_pre_o_0_pos1_c740")
ABS = 1e-6
HOST = 3e-6


def load(p):
    return np.fromfile(p, dtype=np.float32)


def pick(d, key, side):
    needle = f"{side}_{key}_"
    hits = sorted(
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith(".bin") and needle in n
    )
    return hits[0] if hits else None


def cmp(a, b):
    n = min(len(a), len(b))
    mx = mr = 0.0
    idx = -1
    ng = 0
    for i in range(n):
        ae = abs(float(a[i] - b[i]))
        den = max(abs(float(a[i])), abs(float(b[i])), 1e-20)
        re = ae / den
        if ae > mx:
            mx, idx, mr = ae, i, re
        if ae > ABS:
            ng += 1
    return n, mx, mr, idx, ng


spv = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv"
spv_sha = hashlib.sha256(open(spv, "rb").read()).hexdigest().upper()
exe = os.path.join(ev, "pin", "rawr_attn_pre_o_0_pos1_fa40e_r89.exe")
exe_sha = hashlib.sha256(open(exe, "rb").read()).hexdigest().upper()
keys = [
    "ATTN_PRE_O_0_pos1",
    "FFN_DOWN_0_pos0",
    "Q_PRE_ROPE_0_pos1",
    "FFN_NORM_1_pos0",
    "FFN_ACT_2_pos0",
    "FFN_DOWN_2_pos0",
    "FFN_DOWN_2_pos1",
]
lines = [
    "CAND=FA_F16_AVX8_RMSNORM_R89",
    f"SHA256={exe_sha}",
    f"Q4K_SPV_bytes={os.path.getsize(spv)} SHA256={spv_sha}",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
    "CROSS_SHA_CREDIT=0",
]
holds = {}
for k in keys:
    gp = pick(gpu, k, "deep2")
    rp = pick(ref, k, "llama")
    if not rp and k.startswith("FFN_"):
        rp = pick(os.path.join(ev, "stage_dump_gpu_ref"), k, "llama")
    if not gp or not rp:
        lines.append(f"{k}: MISSING gp={bool(gp)} rp={bool(rp)}")
        continue
    n, mx, mr, idx, ng = cmp(load(gp), load(rp))
    under = int(mx <= ABS)
    lines.append(
        f"{k}: maxAbs={mx:.6e} rel={mr:.6e} @idx{idx} n_gt={ng}/{n} UNDER_TOL={under}"
    )
    holds[k] = (mx, under)

# C740 control diffs (norm/act/down)
for k in ["FFN_NORM_1_pos0", "FFN_ACT_2_pos0", "FFN_DOWN_2_pos0"]:
    a, b = pick(gpu, k, "deep2"), pick(c740, k, "deep2")
    if a and b:
        d = np.abs(load(a) - load(b))
        lines.append(
            f"vs_C740_{k}: maxAbs={float(d.max()):.6e} bitexact={float(d.max())==0.0}"
        )

pre = holds.get("ATTN_PRE_O_0_pos1", (None, 0))
ffn0 = holds.get("FFN_DOWN_0_pos0", (None, 0))
ffn2 = holds.get("FFN_DOWN_2_pos0", (None, 0))
qpr = holds.get("Q_PRE_ROPE_0_pos1", (None, 0))
closed = int(pre[0] is not None and pre[0] <= ABS)
host = int(ffn2[0] is not None and ffn2[0] <= HOST)
joint = int(closed == 1 and host == 1 and ffn0[1] == 1 and qpr[1] == 1)
lines += [
    f"ATTN_PRE_O_0_POS1_CLOSE={closed}",
    f"HOLD_FFN_DOWN_0={int(ffn0[1]==1)} HOLD_Q_PRE_ROPE_0={int(qpr[1]==1)}",
    f"HOLD_FFN_DOWN_2_HOSTCLASS={host} FFN_DOWN_2_maxAbs={ffn2[0]}",
    f"JOINT_PASS={joint}",
    "PROMOTE=0 TIP_CLIMB=HOLD",
]
outp = os.path.join(ev, "GPU_PARITY_ATTN_PRE_O_0_POS1_FA40E_R89.compare.log")
open(outp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("\n".join(lines))
