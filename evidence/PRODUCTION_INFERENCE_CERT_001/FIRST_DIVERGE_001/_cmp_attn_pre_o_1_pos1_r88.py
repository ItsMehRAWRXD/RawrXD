# R88 dual-pipe remasure compare on FA006 pin. PROMOTE=0 RELATED!=PASS
import os, hashlib, re
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close006_fa")
ref = os.path.join(ev, "stage_dump_ref_matched")
ABS, REL = 1e-6, 1e-5


def load(p):
    return np.fromfile(p, dtype=np.float32)


def pick(d, key, prefer_n=None):
    hits = []
    for n in os.listdir(d):
        if not n.endswith(".bin"):
            continue
        if f"_{key}_" not in n and not n.startswith(f"deep2_{key}_") and not n.startswith(
            f"llama_{key}_"
        ):
            if key not in n:
                continue
        if key not in n:
            continue
        if re.search(r"_pos1\d_", n):
            continue
        # require exact token boundary for pos keys
        if "_pos" in key and f"_{key}_" not in f"_{n}_".replace(".bin", "_"):
            # fallback: key as substring with layer marker
            if f"{key}_layer" not in n:
                continue
        hits.append(os.path.join(d, n))
    if prefer_n is not None:
        pref = [p for p in hits if f"_n{prefer_n}_" in os.path.basename(p)]
        if pref:
            hits = pref
    hits = sorted(hits)
    return hits[-1] if hits else None


def cmp(a, b):
    n = min(len(a), len(b))
    mx = mr = 0.0
    idx = -1
    ng = 0
    for i in range(n):
        ae = abs(float(a[i] - b[i]))
        den = max(abs(float(a[i])), abs(float(b[i])))
        re = ae / den if den > 1e-20 else ae
        if ae > mx:
            mx, idx, mr = ae, i, re
        if ae > ABS:
            ng += 1
    return n, mx, mr, idx, ng


spv = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv"
spv_sha = hashlib.sha256(open(spv, "rb").read()).hexdigest().upper()
spv_len = os.path.getsize(spv)
exe = os.path.join(ev, "pin", "rawr_attn_pre_o_1_pos1_fa006.exe")
exe_sha = hashlib.sha256(open(exe, "rb").read()).hexdigest().upper()

keys = [
    ("ATTN_NORM_1_pos1", 2048),
    ("Q_PRE_ROPE_1_pos1", 2048),
    ("Q_POST_ROPE_1_pos1", 2048),
    ("K_PRE_ROPE_1_pos0", 256),
    ("K_PRE_ROPE_1_pos1", 256),
    ("V_1_pos0", 256),
    ("V_1_pos1", 256),
    ("ATTN_PRE_O_0_pos1", 2048),
    ("ATTN_PRE_O_1_pos0", 2048),
    ("ATTN_PRE_O_1_pos1", 2048),
    ("ATTN_OUT_1_pos1", 2048),
    ("FFN_DOWN_0_pos0", 2048),
    ("FFN_DOWN_2_pos1", 2048),
]
lines = [
    f"TOL_ABS={ABS:g} TARGET=ATTN_PRE_O_1@pos1",
    "CAND=pin/rawr_attn_pre_o_1_pos1_fa006.exe",
    f"SHA256={exe_sha}",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
    f"Q4K_SPV bytes={spv_len} SHA256={spv_sha}",
    "ISOLATE=dump+compare host/SPV Q/WQ; FA_Q_F32 REFUTED; host square REFUTED",
]
target = None
first = None
holds = {}
for k, pn in keys:
    gp = pick(gpu, f"deep2_{k}", pn)
    rp = pick(ref, f"llama_{k}", pn)
    if not gp or not rp:
        # FFN_DOWN_2 ref may live elsewhere
        if k.startswith("FFN_DOWN_2"):
            alt = os.path.join(ev, "stage_dump_gpu_ref")
            rp = pick(alt, f"llama_{k}", pn) if os.path.isdir(alt) else None
        if not gp or not rp:
            lines.append(f"{k}: MISSING gpu={bool(gp)} ref={bool(rp)}")
            continue
    g, r = load(gp), load(rp)
    n, mx, mr, idx, ng = cmp(g, r)
    under = int(mx <= ABS)
    head = idx // 64 if idx >= 0 else -1
    lines.append(
        f"{k}: maxAbs={mx:.6e} rel={mr:.6e} @idx{idx} head{head} "
        f"n_gt={ng}/{n} UNDER_TOL={under}"
    )
    holds[k] = (mx, under, idx)
    if (not under) and first is None and n == min(len(g), len(r)):
        # skip known Q_POST layout false-hit if sizes mismatched filtered by prefer_n
        if "POST_ROPE" in k and n < 2048:
            continue
        first = (k, mx, idx, head)
    if k == "ATTN_PRE_O_1_pos1":
        target = mx
        lines.append(f"ATTN_PRE_O_1_POS1_CLOSE={int(mx <= ABS)}")
        lines.append(f"AFTER_maxAbs={mx:.6e}")

closed = target is not None and target <= ABS
lines += [
    f"FIRST_SIZE_MATCHED_OPEN={first}",
    f"RESULT={'CLOSED' if closed else 'OPEN'}",
    "ROOT=ATTN_Q_SPV_ULP_FA_F16_AMPLIFY head11",
    "OFFLINE=refQ_POST+gpuKV closes head11 to 3.725290e-09; leaves 9.426847e-06 @idx1836 head28",
    "OFFLINE=FA_Q_F32 reopens L0 PRE_O to 2.648309e-05 (REFUTED)",
    "NEXT_GATE=ATTN_Q_SPV_BITEXACT_WQ_HEAD11_OR_DUAL_PIPE",
    "PROMOTE=0 TIP_CLIMB=HOLD CROSS_SHA_CREDIT=0",
]
outp = os.path.join(ev, "GPU_PARITY_ATTN_Q_SPV_WQ_HEAD11_R88.compare.log")
open(outp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("\n".join(lines))
print("WROTE", outp)
