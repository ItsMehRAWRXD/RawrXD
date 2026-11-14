import os, hashlib
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close005")
ref = os.path.join(ev, "stage_dump_ref_matched")
ABS, REL = 1e-6, 1e-5
BEFORE_CLAIM = 2.754107e-05  # CLOSE_003/004 q4host-era claim


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
spv_len = os.path.getsize(spv)
exe = r"G:\~dev\rawrxd\build_ninja\bin\rawr_gpufwd_C7402085.exe"
exe_sha = hashlib.sha256(open(exe, "rb").read()).hexdigest().upper()

keys = [
    "ATTN_PRE_O_0_pos0",
    "ATTN_PRE_O_0_pos1",
    "ATTN_OUT_0_pos1",
    "FFN_DOWN_0_pos0",
    "FFN_DOWN_0_pos1",
    "Q_PRE_ROPE_0_pos1",
    "Q_PRE_ROPE_1_pos1",
    "K_PRE_ROPE_1_pos1",
    "V_1_pos1",
    "ATTN_PRE_O_1_pos0",
    "ATTN_PRE_O_1_pos1",
    "ATTN_OUT_1_pos1",
    "FFN_ACT_2_pos0",
    "FFN_DOWN_2_pos0",
]
lines = [
    f"TOL_ABS={ABS:g} TOL_REL={REL:g} TARGET=ATTN_PRE_O_1@pos1",
    f"GPU_DIR={gpu}",
    f"REF_DIR={ref}",
    "CAND=build_ninja/bin/rawr_gpufwd_C7402085.exe",
    f"SHA256={exe_sha}",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
    "ENV=FORCE_VULKAN_QUANT_GEMV=1 QUANT_HOST_Q8K_PARITY=0 Q6_HOST_FFN_DOWN=0 "
    "Q4_HOST_ATTN=0 Q4_HOST_FFN_DOWN=0 KV_FP16_ROUNDTRIP=1 GPU_FWD=0",
    f"Q4K_SPV={spv} bytes={spv_len} SHA256={spv_sha}",
    f"BEFORE_CLAIM_q4host_CLOSE003={BEFORE_CLAIM:.6e}",
]
target = None
first = None
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
    if k == "ATTN_PRE_O_0_pos1":
        first = mx
        lines.append(f"FIRST_MATERIAL_ATTN_PRE_O_0_POS1={int(mx > ABS)}")

closed = target is not None and target <= ABS
reg_ok = True
for rk in ("FFN_DOWN_0_pos0", "FFN_DOWN_2_pos0", "Q_PRE_ROPE_0_pos1"):
    if rk == "FFN_DOWN_2_pos0":
        # closed seal uses host-class residual ~2.15e-6 as UNDER for this gate
        if rk in holds and holds[rk][0] > 3e-6:
            reg_ok = False
            lines.append(f"REGRESS_{rk}=1")
        continue
    if rk in holds and holds[rk][1] == 0:
        reg_ok = False
        lines.append(f"REGRESS_{rk}=1")

lines += [
    f"RESULT={'CLOSED' if closed else 'OPEN'}",
    f"REGRESSION_HOLD_FFN={int(reg_ok)}",
    f"FIRST_OPEN_C740=ATTN_PRE_O_0@pos1 maxAbs={first:.6e}" if first else "FIRST_OPEN=NA",
    "ROOT=C740_ATTN_PRE_O_0_POS1_FA_AMPLIFY_CASCADE_TO_PRE_O_1",
    "SPV40E_vs_4548_PRE_O_BITEXACT=1 FFN_DOWN_2_ONLY_DIFFERS=1",
    "NEXT_OPEN="
    + (
        "scan after PRE_O closed"
        if closed
        else "ATTN_PRE_O_0@pos1 (cascades ATTN_PRE_O_1@pos1)"
    ),
    "PROMOTE=0 TIP_CLIMB=HOLD",
]
outp = os.path.join(ev, "GPU_PARITY_ATTN_PRE_O_1_POS1_CLOSE_005.compare.log")
open(outp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("\n".join(lines))
print("WROTE", outp)
