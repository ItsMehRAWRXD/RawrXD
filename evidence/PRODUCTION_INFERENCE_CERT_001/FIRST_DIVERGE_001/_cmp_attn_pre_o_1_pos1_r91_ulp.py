# R91 WQ AVX + ATTN_OUT ULP hold remasure. PROMOTE=0 RELATED!=PASS
import os, hashlib, re, struct
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_r91_ulp")
ctrl = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_r89_ctrl_dp")
ref = os.path.join(ev, "stage_dump_ref_matched")
ABS = 1e-6
IDX747 = 747


def load(p):
    return np.fromfile(p, dtype=np.float32)


def ulp(a, b):
    ai = struct.unpack("<I", struct.pack("<f", float(a)))[0]
    bi = struct.unpack("<I", struct.pack("<f", float(b)))[0]
    return abs(ai - bi)


def pick(d, key, prefer_n=None):
    if not os.path.isdir(d):
        return None
    hits = []
    for n in os.listdir(d):
        if not n.endswith(".bin") or key not in n:
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
    m, idx = 0.0, -1
    ng = 0
    for i in range(n):
        ae = abs(float(a[i] - b[i]))
        if ae > m:
            m, idx = ae, i
        if ae > ABS:
            ng += 1
    return n, m, idx, ng


spv_wq = r"G:\~dev\rawrxd\src\backend\gemv_q4k_r88_dualpipe.spv"
spv_40e = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv"
exe = os.path.join(ev, "pin", "rawr_attn_pre_o_1_pos1_fa006_r91ulp.exe")
exe_sha = hashlib.sha256(open(exe, "rb").read()).hexdigest().upper()
wq_sha = hashlib.sha256(open(spv_wq, "rb").read()).hexdigest().upper()
e40_sha = hashlib.sha256(open(spv_40e, "rb").read()).hexdigest().upper()

keys_ref = [
    ("ATTN_PRE_O_1_pos1", 2048),
    ("Q_PRE_ROPE_1_pos1", 2048),
    ("FFN_DOWN_2_pos1", 2048),
]
keys_ctrl = [
    ("ATTN_OUT_0_pos1", 2048),
    ("FFN_NORM_0_pos1", 2048),
    ("FFN_GATE_0_pos1", 5632),
    ("FFN_DOWN_2_pos1", 2048),
    ("ATTN_PRE_O_1_pos1", 2048),
]
lines = [
    f"TOL_ABS={ABS:g} TARGET=ATTN_PRE_O_1@pos1 HOLD=ATTN_OUT_ULP_3LSB",
    "CAND=pin/rawr_attn_pre_o_1_pos1_fa006_r91ulp.exe",
    f"EXE_SHA256={exe_sha}",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
    f"SPV_WQ_AVX bytes={os.path.getsize(spv_wq)} SHA256={wq_sha}",
    f"SPV_40E_FFN bytes={os.path.getsize(spv_40e)} SHA256={e40_sha}",
    "PIPE=q4k_avx_wq_pipe_(BE085)+flags1; ATTN_OUT_ULP_HOLD=1; FFN=40E",
]
pre_o = gate = fnorm = None
first = None
for k, pn in keys_ref:
    gp, rp = pick(gpu, f"deep2_{k}", pn), pick(ref, f"llama_{k}", pn)
    if k.startswith("FFN_DOWN_2") and not rp:
        rp = pick(os.path.join(ev, "stage_dump_gpu_ref"), f"llama_{k}", pn)
    if not gp or not rp:
        lines.append(f"REF {k}: MISSING")
        continue
    n, m, idx, ng = mx(load(gp), load(rp))
    lines.append(
        f"REF {k}: maxAbs={m:.6e} @idx{idx} n_gt={ng}/{n} UNDER={int(m <= ABS)}"
    )
    if k == "ATTN_PRE_O_1_pos1":
        pre_o = m
    if k == "Q_PRE_ROPE_1_pos1":
        g, r = load(gp), load(rp)
        if len(g) > IDX747 and len(r) > IDX747:
            lines.append(
                f"Q_PRE@747 gpu={float(g[IDX747]):.10e} ref={float(r[IDX747]):.10e} "
                f"ulp_ref={ulp(g[IDX747], r[IDX747])}"
            )
    if m > ABS and first is None:
        first = (k, m, idx)

for k, pn in keys_ctrl:
    gp, cp = pick(gpu, f"deep2_{k}", pn), pick(ctrl, f"deep2_{k}", pn)
    if not gp or not cp:
        lines.append(f"CTRL {k}: MISSING")
        continue
    n, m, idx, ng = mx(load(gp), load(cp))
    lines.append(
        f"CTRL {k}: maxAbs={m:.6e} @idx{idx} n_gt={ng}/{n} UNDER={int(m <= ABS)}"
    )
    if k == "FFN_GATE_0_pos1":
        gate = m
    if k == "FFN_NORM_0_pos1":
        fnorm = m
    if k == "FFN_DOWN_2_pos1":
        lines.append(f"FFN_DOWN_2_HELD_VS_CTRL={int(m <= ABS)}")

closed = pre_o is not None and pre_o <= ABS
gate_held = gate is not None and gate <= ABS
# RELATED: FFN_GATE held vs FA006 while PRE_O still open (cascade broken)
related = gate_held and not closed
lines += [
    f"maxAbs_PRE_O_1={pre_o}",
    f"maxAbs_FFN_GATE_0_vs_ctrl={gate}",
    f"maxAbs_FFN_NORM_0_vs_ctrl={fnorm}",
    f"FFN_GATE_0_HELD={int(gate_held) if gate is not None else 0}",
    f"FIRST_REF_OPEN={first}",
    f"CLOSED={int(closed)}",
    f"RESULT={'RELATED' if related else ('CLOSED' if closed else 'BLOCKED')}",
    "ROOT=ATTN_Q_WQ_NO_FFN_NORM_ULP_R91",
    "PROMOTE=0 TIP_CLIMB=HOLD CROSS_SHA_CREDIT=0 RELATED!=PASS",
]
outp = os.path.join(ev, "GPU_PARITY_ATTN_Q_WQ_NO_FFN_NORM_ULP_R91.compare.log")
open(outp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("\n".join(lines))
print("WROTE", outp)
