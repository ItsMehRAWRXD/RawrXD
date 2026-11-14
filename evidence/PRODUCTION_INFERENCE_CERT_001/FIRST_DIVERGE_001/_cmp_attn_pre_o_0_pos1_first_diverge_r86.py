"""Walk host(REF) vs deep2 intermediates for ATTN_PRE_O_0@pos1. PROMOTE=0."""
import os, hashlib, re
from datetime import datetime
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
ref = os.path.join(ev, "stage_dump_ref_matched")
ABS = 1e-6

# Ordered ops on the ATTN_PRE_O_0@pos1 path (before O-proj).
ORDER = [
    "PROMPT_EMBED_pos1",
    "ATTN_NORM_0_pos1",
    "V_0_pos1",
    "Q_LINEAR_0_pos1",
    "K_LINEAR_0_pos1",
    "Q_NORM_0_pos1",
    "K_NORM_0_pos1",
    "Q_PRE_ROPE_0_pos1",
    "K_PRE_ROPE_0_pos1",
    "Q_POST_ROPE_0_pos1",
    "K_POST_ROPE_0_pos1",
    "ATTN_PRE_O_0_pos1",
]


def load(p):
    return np.fromfile(p, dtype=np.float32)


def pick(d, key, side, want_nelem=None):
    needle = f"{side}_{key}_"
    hits = [
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith(".bin") and needle in n
    ]
    if not hits:
        return None
    if want_nelem is not None:
        matched = [p for p in hits if os.path.getsize(p) == want_nelem * 4]
        if matched:
            # Prefer full n2048/n256 dumps (largest seq among matches).
            return sorted(matched)[-1]
    # Prefer largest dump (full vector over head slice).
    return sorted(hits, key=lambda p: (os.path.getsize(p), p))[-1]


def cmp(a, b):
    if len(a) != len(b):
        return min(len(a), len(b)), float("nan"), -1, -1, True
    n = len(a)
    mx = 0.0
    idx = -1
    ng = 0
    for i in range(n):
        ae = abs(float(a[i] - b[i]))
        if ae > mx:
            mx, idx = ae, i
        if ae > ABS:
            ng += 1
    return n, mx, idx, ng, False


def walk(gpu_dir, label, exe_path):
    lines = [f"PIN={label}", f"GPU_DIR={gpu_dir}"]
    if exe_path and os.path.isfile(exe_path):
        h = hashlib.sha256(open(exe_path, "rb").read()).hexdigest().upper()
        lines.append(f"EXE_SHA256={h}")
    spv = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv"
    lines.append(
        f"SPV_SHA256={hashlib.sha256(open(spv,'rb').read()).hexdigest().upper()} "
        f"LEN={os.path.getsize(spv)}"
    )
    first = None
    for k in ORDER:
        gp = pick(gpu_dir, k, "deep2")
        if not gp:
            lines.append(f"{k}: MISSING gpu")
            continue
        g = load(gp)
        rp = pick(ref, k, "llama", want_nelem=len(g))
        if not rp:
            lines.append(f"{k}: MISSING ref (want_nelem={len(g)})")
            continue
        n, mx, idx, ng, size_mismatch = cmp(g, load(rp))
        if size_mismatch:
            lines.append(
                f"{k}: SIZE_MISMATCH gpu={len(g)} ref={os.path.getsize(rp)//4} "
                f"SKIPPED_AS_LAYOUT"
            )
            continue
        under = int(mx <= ABS)
        head = idx // 64 if idx >= 0 else -1
        lines.append(
            f"{k}: maxAbs={mx:.6e} @idx{idx} head{head} n_gt={ng}/{n} UNDER_TOL={under}"
        )
        if first is None and under == 0:
            first = k
            lines.append(f"FIRST_DIVERGE_OP={k} maxAbs={mx:.6e} @idx{idx}")
    if first is None:
        lines.append("FIRST_DIVERGE_OP=NONE_ON_PRE_O_0_PATH")
    return first, lines


def main():
    asof = datetime.now().isoformat(timespec="seconds")
    out_lines = [
        "ATTN_PRE_O_0_POS1_FIRST_DIVERGE_R86",
        f"ASOF={asof}",
        f"TOL_ABS={ABS:g}",
        "REF=stage_dump_ref_matched",
        "PROMOTE=0 TIP_CLIMB=HOLD CROSS_SHA_CREDIT=0",
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
            r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\pin\rawr_attn_pre_o_1_pos1_fa006.exe",
        ),
    ]
    results = {}
    for label, gdir, exe in pins:
        if not os.path.isdir(gdir):
            out_lines.append(f"PIN={label} DUMP_MISSING")
            continue
        first, lines = walk(gdir, label, exe)
        results[label] = first
        out_lines += lines + [""]
    out_lines.append(f"C740_FIRST={results.get('C740')}")
    out_lines.append(f"FA006_FIRST={results.get('FA006')}")
    outp = os.path.join(ev, "GPU_PARITY_ATTN_PRE_O_0_POS1_FIRST_DIVERGE_R86.compare.log")
    open(outp, "w", encoding="utf-8").write("\n".join(out_lines) + "\n")
    print("\n".join(out_lines))
    print("WROTE", outp)


if __name__ == "__main__":
    main()
