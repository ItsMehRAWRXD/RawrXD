"""FA006 remasure compare for ATTN_PRE_O_0@pos1. PROMOTE=0 RELATED≠PASS."""
import os, hashlib
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close006_fa")
ref = os.path.join(ev, "stage_dump_ref_matched")
ABS = 1e-6


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
    mx = 0.0
    idx = -1
    ng = 0
    for i in range(n):
        ae = abs(float(a[i] - b[i]))
        if ae > mx:
            mx, idx = ae, i
        if ae > ABS:
            ng += 1
    return n, mx, idx, ng


spv = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv"
exe = os.path.join(ev, "pin", "rawr_attn_pre_o_1_pos1_fa006.exe")
exe_sha = hashlib.sha256(open(exe, "rb").read()).hexdigest().upper()
spv_sha = hashlib.sha256(open(spv, "rb").read()).hexdigest().upper()
keys = [
    "ATTN_PRE_O_0_pos0",
    "ATTN_PRE_O_0_pos1",
    "Q_PRE_ROPE_0_pos1",
    "Q_POST_ROPE_0_pos1",
    "K_POST_ROPE_0_pos1",
    "V_0_pos1",
    "ATTN_OUT_0_pos1",
    "FFN_DOWN_0_pos0",
    "FFN_DOWN_2_pos1",
    "ATTN_PRE_O_1_pos1",
    "V_1_pos0",
]
lines = [
    f"TOL_ABS={ABS:g} TARGET=ATTN_PRE_O_0@pos1 PIN=FA006",
    f"SHA256={exe_sha}",
    f"SPV_SHA256={spv_sha} LEN={os.path.getsize(spv)}",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
]
target = None
for k in keys:
    gp = pick(gpu, k, "deep2")
    rp = pick(ref, k, "llama")
    if not gp or not rp:
        lines.append(f"{k}: MISSING gpu={bool(gp)} ref={bool(rp)}")
        continue
    n, mx, idx, ng = cmp(load(gp), load(rp))
    under = int(mx <= ABS)
    head = idx // 64 if idx >= 0 else -1
    lines.append(
        f"{k}: maxAbs={mx:.6e} @idx{idx} head{head} n_gt={ng}/{n} UNDER_TOL={under}"
    )
    if k == "ATTN_PRE_O_0_pos1":
        target = mx
        lines.append(f"ATTN_PRE_O_0_POS1_CLOSE={int(mx <= ABS)}")
        lines.append(f"AFTER_maxAbs={mx:.6e}")
closed = target is not None and target <= ABS
lines += [
    f"RESULT={'CLOSED' if closed else 'OPEN'}",
    "CROSS_SHA_CREDIT=0 PROMOTE=0 TIP_CLIMB=HOLD RELATED_NE_CERT_PASS=1",
]
outp = os.path.join(ev, "GPU_PARITY_ATTN_PRE_O_0_POS1_FA006_REMEASURE_R86.compare.log")
open(outp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("\n".join(lines))
print("WROTE", outp)
