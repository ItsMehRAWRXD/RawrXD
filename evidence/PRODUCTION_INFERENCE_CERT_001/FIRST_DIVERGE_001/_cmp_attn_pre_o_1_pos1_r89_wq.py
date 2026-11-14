# R89 WQ-only clean-relink remasure. PROMOTE=0 RELATED!=PASS
import os, hashlib, re, struct
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_r89_wq")
ref = os.path.join(ev, "stage_dump_ref_matched")
ABS, REL = 1e-6, 1e-5
IDX747 = 747


def load(p):
    return np.fromfile(p, dtype=np.float32)


def ulp(a, b):
    ai = struct.unpack("<I", struct.pack("<f", float(a)))[0]
    bi = struct.unpack("<I", struct.pack("<f", float(b)))[0]
    return abs(ai - bi)


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


spv_wq = r"G:\~dev\rawrxd\src\backend\gemv_q4k_r88_dualpipe.spv"
spv_40e = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv"
exe = os.path.join(ev, "pin", "rawr_attn_pre_o_1_pos1_fa006_r89wq.exe")
exe_sha = hashlib.sha256(open(exe, "rb").read()).hexdigest().upper()
wq_sha = hashlib.sha256(open(spv_wq, "rb").read()).hexdigest().upper()
e40_sha = hashlib.sha256(open(spv_40e, "rb").read()).hexdigest().upper()

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
    "CAND=pin/rawr_attn_pre_o_1_pos1_fa006_r89wq.exe",
    f"EXE_SHA256={exe_sha}",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
    f"SPV_WQ_AVX bytes={os.path.getsize(spv_wq)} SHA256={wq_sha}",
    f"SPV_40E_CTRL bytes={os.path.getsize(spv_40e)} SHA256={e40_sha}",
    "PIPE=WQ_ONLY_PC_FLAG + dualpipe SPV; WO/FFN generic branch",
]
target = None
first = None
q747 = {}
for k, pn in keys:
    gp = pick(gpu, f"deep2_{k}", pn)
    rp = pick(ref, f"llama_{k}", pn)
    if not gp or not rp:
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
    if k in ("Q_PRE_ROPE_1_pos1", "Q_POST_ROPE_1_pos1") and len(g) > IDX747 and len(r) > IDX747:
        lines.append(
            f"{k}@747 gpu={float(g[IDX747]):.10e} ref={float(r[IDX747]):.10e} "
            f"abs={abs(float(g[IDX747]-r[IDX747])):.6e} ulp_ref={ulp(g[IDX747], r[IDX747])}"
        )
        q747[k] = (float(g[IDX747]), float(r[IDX747]), ulp(g[IDX747], r[IDX747]))
    if (not under) and first is None:
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
    "ROOT=ATTN_Q_SPV_WQ_ONLY_AVX_PIPE",
    "PROMOTE=0 TIP_CLIMB=HOLD CROSS_SHA_CREDIT=0 RELATED!=PASS",
]
outp = os.path.join(ev, "GPU_PARITY_ATTN_Q_SPV_WQ_ONLY_AVX_R89.compare.log")
open(outp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("\n".join(lines))
print("WROTE", outp)
