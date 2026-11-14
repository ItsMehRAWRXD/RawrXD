# GATE_UP_ULP_TIGHTEN remasure compare — host Q4 FFN under FORCE.
# PROMOTE=0 MATCH_PASS=0 TIP_CLIMB=HOLD INVENT_PASS=0
import os, glob, struct, math, re
from datetime import datetime

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_ffn_act2_hostq4")
ref_ffn = os.path.join(ev, "stage_dump_ffn_act2_c740_after_ref")
ref_gpu = os.path.join(ev, "stage_dump_gpu_fix")
ref_final = os.path.join(ev, "_cmp_finalnorm_stage")
out_path = os.path.join(ev, "GPU_PARITY_FFN_ACT_2_HOSTQ4_001.compare.txt")
seal_gui = (
    r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001"
    r"\GUI_TOP25_VALUATION_001\gpu\GPU_PARITY_FFN_ACT_2_HOSTQ4_001.compare.txt"
)

# Class abs tols (OR-law material); functional AND-law separate below.
TOL = {
    "FFN_GATE_2": 1e-5,
    "FFN_UP_2": 1e-5,
    "FFN_ACT_2": 1e-5,
    "LAYER13_OUT": 1e-4,
    "ATTN_PRE_O_14": 1e-4,
    "ATTN_OUT_14": 1e-4,
    "FINAL_NORM": 1e-4,
}
REL_TOL = 1e-4
FUNC_ABS = 1e-4
FUNC_REL = 1e-3
BEFORE_ACT = 4.577637e-05
BEFORE_ATTN14 = 3.617927e-04
BEFORE_FINAL = 5.380497e-01

PROBES = [
    ("FFN_GATE_2", gpu, "deep2_FFN_GATE_2_pos0_layer0_full_n5632_*.bin",
     ref_ffn, "llama_FFN_GATE_2_pos0_layer0_full_n5632_*.bin"),
    ("FFN_UP_2", gpu, "deep2_FFN_UP_2_pos0_layer0_full_n5632_*.bin",
     ref_ffn, "llama_FFN_UP_2_pos0_layer0_full_n5632_*.bin"),
    ("FFN_ACT_2", gpu, "deep2_FFN_ACT_2_pos0_layer0_full_n5632_*.bin",
     ref_ffn, "llama_FFN_ACT_2_pos0_layer0_full_n5632_*.bin"),
    ("LAYER13_OUT", gpu, "deep2_LAYER13_OUT_pos0_layer0_full_n2048_*.bin",
     ref_gpu, "llama_LAYER13_OUT_pos0_layer0_full_n2048_*.bin"),
    ("ATTN_PRE_O_14", gpu, "deep2_ATTN_PRE_O_14_pos0_layer0_full_n2048_*.bin",
     ref_gpu, "llama_ATTN_PRE_O_14_pos0_layer0_full_n2048_*.bin"),
    ("ATTN_OUT_14", gpu, "deep2_ATTN_OUT_14_pos0_layer0_full_n2048_*.bin",
     ref_gpu, "llama_ATTN_OUT_14_pos0_layer0_full_n2048_*.bin"),
    ("FINAL_NORM", gpu, "deep2_FINAL_NORM_pos0_layer0_full_n2048_*.bin",
     ref_final, "llama_REF_FINAL_HIDDEN_pos0.bin"),
]


def load(path):
    with open(path, "rb") as f:
        b = f.read()
    n = len(b) // 4
    return struct.unpack("<%df" % n, b), b


def fnv(data):
    h = 0xCBF29CE484222325
    for c in data:
        h ^= c
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"


def stats(a, b):
    n = min(len(a), len(b))
    s = 0.0
    mx = 0.0
    peak_i = -1
    for i in range(n):
        d = abs(a[i] - b[i])
        s += d * d
        if d > mx:
            mx = d
            peak_i = i
    l2b = math.sqrt(sum(x * x for x in b[:n]))
    rms = math.sqrt(s / n) if n else 0.0
    rel = rms / (l2b + 1e-30)
    max_rel = 0.0
    for i in range(n):
        den = abs(b[i]) if abs(b[i]) > 1e-30 else 1e-30
        r = abs(a[i] - b[i]) / den
        if r > max_rel:
            max_rel = r
    return n, rms, rel, mx, max_rel, peak_i


def seqnum(p):
    m = re.search(r"seq(\d+)", os.path.basename(p))
    return int(m.group(1)) if m else 999999


def pick(dirpath, pat):
    if not pat.endswith(".bin") or "*" in pat:
        gs = glob.glob(os.path.join(dirpath, pat))
        if not gs:
            return None
        return sorted(gs, key=seqnum)[0]
    p = os.path.join(dirpath, pat)
    return p if os.path.isfile(p) else None


def main():
    lines = []
    lines.append("GPU_PARITY_FFN_ACT_2_HOSTQ4_001.compare")
    lines.append(
        "PAIR=stage_dump_ffn_act2_hostq4 vs c740_after_ref / gpu_fix / "
        "finalnorm_stage"
    )
    lines.append(
        "EXE=pin/rawr_ffn_act2_hostq4.exe SHA256=CEC31155… "
        "FORCE_VULKAN=1 PARITY=1 HOST_Q4_ROWS_GT_COLS=EXERCISED"
    )
    lines.append(f"ASOF={datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"BEFORE_FFN_ACT_2={BEFORE_ACT:.6e}")
    lines.append(f"BEFORE_ATTN_OUT_14={BEFORE_ATTN14:.6e}")
    lines.append(f"BEFORE_FINAL_NORM={BEFORE_FINAL:.6e}")

    results = {}
    for name, gdir, gpat, rdir, rpat in PROBES:
        gp = pick(gdir, gpat)
        rp = pick(rdir, rpat)
        abs_tol = TOL[name]
        if not gp or not rp:
            lines.append(f"{name}: MISSING g={bool(gp)} r={bool(rp)}")
            continue
        a, ra = load(gp)
        b, rb = load(rp)
        n, rms, rel, mx, max_rel, peak_i = stats(a, b)
        fg, fr = fnv(ra), fnv(rb)
        material = (mx > abs_tol) or (rel > REL_TOL)
        func_fail = (mx > FUNC_ABS) and (max_rel > FUNC_REL)
        if fg == fr:
            kind = "EXACT"
        elif material:
            kind = "MATERIAL_DIVERGENCE"
        else:
            kind = "BITWISE_DIFF"
        under = "Y" if not material else "N"
        lines.append(
            f"{name}: kind={kind} maxAbs={mx:.6e} rel_rms={rel:.6e} "
            f"maxRel={max_rel:.6e} UNDER_TOL={under} "
            f"FUNCTIONAL_FAIL={1 if func_fail else 0} "
            f"peak_i={peak_i} gpu[{peak_i}]={a[peak_i]:.9e} "
            f"ref[{peak_i}]={b[peak_i]:.9e} gpu_fnv={fg} ref_fnv={fr} "
            f"gpu={os.path.basename(gp)} ref={os.path.basename(rp)}"
        )
        results[name] = {
            "mx": mx,
            "material": material,
            "func": func_fail,
            "under": under,
        }

    act = results.get("FFN_ACT_2", {})
    attn = results.get("ATTN_OUT_14", {})
    fin = results.get("FINAL_NORM", {})
    lines.append(
        f"AFTER_FFN_ACT_2_maxAbs={act.get('mx', float('nan')):.6e} "
        f"UNDER_TOL={act.get('under', '?')}"
    )
    lines.append(
        f"AFTER_ATTN_OUT_14_maxAbs={attn.get('mx', float('nan')):.6e} "
        f"FUNCTIONAL_FAIL={1 if attn.get('func') else 0}"
    )
    lines.append(
        f"AFTER_FINAL_NORM_maxAbs={fin.get('mx', float('nan')):.6e} "
        f"FUNCTIONAL_FAIL={1 if fin.get('func') else 0}"
    )
    lines.append("MATCH_PASS=0")
    lines.append("INVENT_PASS=0")
    lines.append("PROMOTE=0")
    lines.append("TIP_CLIMB=HOLD")
    lines.append("DENSE_MATCH=HOLD")
    lines.append("ENTERPRISE_CHECKLIST_PASS=0")
    text = "\n".join(lines) + "\n"
    for p in (out_path, seal_gui):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    print(text)


if __name__ == "__main__":
    main()
