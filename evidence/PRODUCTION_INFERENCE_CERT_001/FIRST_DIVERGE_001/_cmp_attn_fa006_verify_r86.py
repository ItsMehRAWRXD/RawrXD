"""Verify FA006 PRE_O_0@pos1 vs CLOSE_005 fixture. RELATED!=PASS. PROMOTE=0."""
import os, hashlib
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
ref = os.path.join(ev, "stage_dump_ref_matched")
ABS = 1e-6
CLAIM = 3.488640e-08


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


def run_pin(label, gpu_dir, exe_path, keys):
    lines = [
        f"PIN={label}",
        f"GPU_DIR={gpu_dir}",
        f"REF_DIR={ref}",
        f"CAND={exe_path}",
    ]
    if os.path.isfile(exe_path):
        h = hashlib.sha256(open(exe_path, "rb").read()).hexdigest().upper()
        lines.append(f"EXE_SHA256={h}")
    else:
        lines.append("EXE_SHA256=MISSING")
    spv = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv"
    lines.append(
        f"SPV_SHA256={hashlib.sha256(open(spv,'rb').read()).hexdigest().upper()} "
        f"LEN={os.path.getsize(spv)}"
    )
    lines.append(
        "ENV=FORCE_VULKAN_QUANT_GEMV=1 Q4_HOST_ATTN=0 Q4_HOST_FFN_DOWN=0 "
        "KV_FP16_ROUNDTRIP=1 GPU_FWD=0 PROMPT_IDS=1,15043"
    )
    lines.append(f"FIXTURE=CLOSE_005 REF=stage_dump_ref_matched TOL_ABS={ABS:g}")
    holds = {}
    for k in keys:
        gp = pick(gpu_dir, k, "deep2")
        rp = pick(ref, k, "llama")
        if not rp and k.startswith("FFN_"):
            rp = pick(os.path.join(ev, "stage_dump_gpu_ref"), k, "llama")
        if not gp or not rp:
            lines.append(f"{k}: MISSING gpu={bool(gp)} ref={bool(rp)}")
            continue
        n, mx, mr, idx, ng = cmp(load(gp), load(rp))
        under = int(mx <= ABS)
        lines.append(
            f"{k}: maxAbs={mx:.6e} rel={mr:.6e} @idx{idx} "
            f"n_gt={ng}/{n} UNDER_TOL={under}"
        )
        holds[k] = (mx, under)
    return lines, holds


def main():
    keys = [
        "ATTN_PRE_O_0_pos0",
        "ATTN_PRE_O_0_pos1",
        "Q_PRE_ROPE_0_pos1",
        "ATTN_OUT_0_pos1",
        "FFN_DOWN_0_pos0",
        "FFN_DOWN_2_pos1",
        "Q_PRE_ROPE_1_pos1",
        "ATTN_PRE_O_1_pos0",
        "ATTN_PRE_O_1_pos1",
        "V_1_pos0",
    ]
    asof = datetime.now().isoformat(timespec="seconds")
    out = [
        "BR_ATTN_FA006_VERIFY_R86_COMPARE",
        f"ASOF={asof}",
        f"CLAIM_FA006_PRE_O_0={CLAIM:.6e}",
        "PROMOTE=0 TIP_CLIMB=HOLD CROSS_SHA_CREDIT=0 RELATED!=PASS",
        "",
    ]
    pins = [
        (
            "C740",
            os.path.join(ev, "stage_dump_attn_pre_o_0_pos1_c740"),
            r"G:\~dev\rawrxd\build_ninja\bin\rawr_gpufwd_C7402085.exe",
        ),
        (
            "FA006",
            os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close006_fa"),
            os.path.join(ev, "pin", "rawr_attn_pre_o_1_pos1_fa006.exe"),
        ),
    ]
    summary = {}
    for label, gdir, exe in pins:
        lines, holds = run_pin(label, gdir, exe, keys)
        out += lines
        pre0 = holds.get("ATTN_PRE_O_0_pos1", (None, 0))
        pre1 = holds.get("ATTN_PRE_O_1_pos1", (None, 0))
        summary[label] = (pre0, pre1)
        if pre0[0] is not None:
            out.append(
                f"{label}_PRE_O_0_pos1 maxAbs={pre0[0]:.6e} "
                f"UNDER_TOL={pre0[1]} CLOSED={int(pre0[0] <= ABS)}"
            )
        if pre1[0] is not None:
            out.append(
                f"{label}_PRE_O_1_pos1 maxAbs={pre1[0]:.6e} "
                f"UNDER_TOL={pre1[1]} CLOSED={int(pre1[0] <= ABS)}"
            )
        out.append("")

    fa = summary.get("FA006", ((None, 0), (None, 0)))
    c7 = summary.get("C740", ((None, 0), (None, 0)))
    fa_pre0 = fa[0][0]
    verified = int(fa_pre0 is not None and fa_pre0 <= ABS)
    out += [
        f"VERIFIED_FA006={verified}",
        f"PRE_O_0_maxAbs_FA006={fa_pre0:.6e}" if fa_pre0 is not None else "PRE_O_0_maxAbs_FA006=NA",
        f"PRE_O_0_maxAbs_C740={c7[0][0]:.6e}" if c7[0][0] is not None else "PRE_O_0_maxAbs_C740=NA",
        f"PRE_O_1_maxAbs_FA006={fa[1][0]:.6e}" if fa[1][0] is not None else "PRE_O_1_maxAbs_FA006=NA",
        f"PRE_O_1_maxAbs_C740={c7[1][0]:.6e}" if c7[1][0] is not None else "PRE_O_1_maxAbs_C740=NA",
        "FIRST_DIVERGE_OP="
        + (
            "ATTN_PRE_O_1_pos1"
            if verified
            else "ATTN_PRE_O_0_pos1"
        ),
        "RESULT=RELATED" if verified else "RESULT=RELATED_CLOSE005_CONTROLLING",
        "PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0",
    ]
    outp = os.path.join(ev, "GPU_PARITY_ATTN_FA006_VERIFY_R86.compare.log")
    open(outp, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print("\n".join(out))
    print("WROTE", outp)


if __name__ == "__main__":
    main()
