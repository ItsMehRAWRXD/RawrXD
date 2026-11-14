import os, hashlib
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close005_postrope")
ref = os.path.join(ev, "stage_dump_ref_matched")
ABS, REL = 1e-6, 1e-5
BEFORE = 2.754107e-05


def load(p):
    return np.fromfile(p, dtype=np.float32)


def pick(d, key, side):
    needle = f"{side}_{key}_"
    hits = sorted(
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith(".bin")
        and needle in n
        and ("_n2048_" in n or "_n256_" in n or "_n5632_" in n)
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
spv_len = os.path.getsize(spv)
exe = os.path.join(ev, "pin", "rawr_attn_pre_o_1_pos1_postrope.exe")
exe_sha = hashlib.sha256(open(exe, "rb").read()).hexdigest().upper()

keys = [
    "ATTN_PRE_O_0_pos0",
    "ATTN_PRE_O_0_pos1",
    "FFN_DOWN_0_pos0",
    "Q_PRE_ROPE_0_pos1",
    "Q_POST_ROPE_0_pos1",
    "Q_PRE_ROPE_1_pos1",
    "Q_POST_ROPE_1_pos1",
    "K_POST_ROPE_1_pos0",
    "K_POST_ROPE_1_pos1",
    "V_1_pos0",
    "V_1_pos1",
    "ATTN_PRE_O_1_pos0",
    "ATTN_PRE_O_1_pos1",
    "ATTN_OUT_1_pos1",
    "FFN_DOWN_2_pos0",
]
lines = [
    f"TOL_ABS={ABS:g} TOL_REL={REL:g} TARGET=ATTN_PRE_O_1@pos1",
    f"GPU_DIR={gpu}",
    f"REF_DIR={ref}",
    "CAND=pin/rawr_attn_pre_o_1_pos1_postrope.exe",
    f"SHA256={exe_sha}",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
    "ENV=FORCE_VULKAN_QUANT_GEMV=1 Q4_HOST_ATTN=0 Q4_HOST_FFN_DOWN=0 "
    "KV_FP16_ROUNDTRIP=1 GPU_FWD=0",
    f"Q4K_SPV={spv} bytes={spv_len} SHA256={spv_sha}",
    f"BEFORE_CLAIM_CLOSE004={BEFORE:.6e}",
]
target = None
holds = {}
for k in keys:
    gp = pick(gpu, k, "deep2")
    rp = pick(ref, k, "llama")
    if not rp and k.startswith("FFN_"):
        rp = pick(os.path.join(ev, "stage_dump_gpu_ref"), k, "llama")
    if not gp or not rp:
        lines.append(f"{k}: MISSING gpu={bool(gp)} ref={bool(rp)}")
        continue
    n, mx, mr, idx, ng = cmp(load(gp), load(rp))
    under = int(mx <= ABS)
    lines.append(
        f"{k}: maxAbs={mx:.6e} rel={mr:.6e} @idx{idx} n_gt={ng}/{n} UNDER_TOL={under}"
    )
    holds[k] = (mx, under)
    if k == "ATTN_PRE_O_1_pos1":
        target = mx
        lines.append(f"ATTN_PRE_O_1_POS1_CLOSE={int(mx <= ABS)}")
        lines.append(f"AFTER_maxAbs={mx:.6e}")

closed = target is not None and target <= ABS
reg_ok = True
for rk, lim in (
    ("FFN_DOWN_0_pos0", ABS),
    ("ATTN_PRE_O_0_pos1", ABS),
    ("Q_PRE_ROPE_1_pos1", ABS),
):
    if rk in holds and holds[rk][0] > lim:
        reg_ok = False
        lines.append(f"REGRESS_{rk}=1")
if "FFN_DOWN_2_pos0" in holds and holds["FFN_DOWN_2_pos0"][0] > 3e-6:
    reg_ok = False
    lines.append("REGRESS_FFN_DOWN_2_pos0=1")

lines += [
    f"RESULT={'CLOSED' if closed else 'OPEN'}",
    f"HOLD_FFN_PREO0_QPREROPE={int(reg_ok)}",
    "ROOT=POST_ROPE_L1_FA_ABLATION_PENDING_SEE_ablate",
    "NEXT_OPEN="
    + (
        "scan after PRE_O closed"
        if closed
        else f"ATTN_PRE_O_1@pos1 maxAbs={target:.6e}"
        if target is not None
        else "ATTN_PRE_O_1@pos1 MISSING"
    ),
    "PROMOTE=0 TIP_CLIMB=HOLD",
]
outp = os.path.join(ev, "GPU_PARITY_ATTN_PRE_O_1_POS1_CLOSE_005.compare.log")
open(outp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("\n".join(lines))
print("WROTE", outp)
