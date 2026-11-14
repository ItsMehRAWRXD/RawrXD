# Layer2+ MATERIAL scan: stage_dump_layer2_plus_C7402085 vs stage_dump_gpu_fix
# Class tol law from GPU_PARITY_FIRST_MATERIAL_DIVERGENCE_001
# PROMOTE=0 TIP_CLIMB=HOLD MATCH_PASS=0 INVENT_PASS=0
import os, glob, struct, math, re
from datetime import datetime

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_layer2_plus_C7402085")
ref = os.path.join(ev, "stage_dump_gpu_fix")
seal_gpu = (
    r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001"
    r"\GUI_TOP25_VALUATION_001\gpu"
)

TOL = {
    "EMBED": (1e-6, 1e-5),
    "NORM": (1e-5, 1e-4),
    "LINEAR": (1e-5, 1e-4),
    "ATTN": (1e-4, 1e-3),
    "FFN": (1e-5, 1e-4),
}

# Ordered per-layer probe (same shape as layer1 seal scan).
# Q_PRE_ROPE/V often absent as llama_* for L>=2 in gpu_fix — skip if missing.
PER_LAYER = [
    ("ATTN_NORM_{L}", "NORM", "deep2_ATTN_NORM_{L}_pos0_layer0_full_n2048_*.bin",
     "llama_ATTN_NORM_{L}_pos0_layer0_full_n2048_*.bin"),
    ("Q_PRE_ROPE_{L}", "LINEAR", "deep2_Q_PRE_ROPE_{L}_pos0_layer0_full_n2048_*.bin",
     "llama_Q_PRE_ROPE_{L}_pos0_layer0_full_n2048_*.bin"),
    ("V_{L}", "LINEAR", "deep2_V_{L}_pos0_layer0_full_n256_*.bin",
     "llama_V_{L}_pos0_layer0_full_n256_*.bin"),
    ("ATTN_PRE_O_{L}", "ATTN", "deep2_ATTN_PRE_O_{L}_pos0_layer0_full_n2048_*.bin",
     "llama_ATTN_PRE_O_{L}_pos0_layer0_full_n2048_*.bin"),
    ("ATTN_OUT_{L}", "ATTN", "deep2_ATTN_OUT_{L}_pos0_layer0_full_n2048_*.bin",
     "llama_ATTN_OUT_{L}_pos0_layer0_full_n2048_*.bin"),
    ("FFN_INP_{L}", "FFN", "deep2_FFN_INP_{L}_pos0_layer0_full_n2048_*.bin",
     "llama_FFN_INP_{L}_pos0_layer0_full_n2048_*.bin"),
    ("FFN_NORM_{L}", "NORM", "deep2_FFN_NORM_{L}_pos0_layer0_full_n2048_*.bin",
     "llama_FFN_NORM_{L}_pos0_layer0_full_n2048_*.bin"),
    ("FFN_GATE_{L}", "FFN", "deep2_FFN_GATE_{L}_pos0_layer0_full_n5632_*.bin",
     "llama_FFN_GATE_{L}_pos0_layer0_full_n5632_*.bin"),
    ("FFN_UP_{L}", "FFN", "deep2_FFN_UP_{L}_pos0_layer0_full_n5632_*.bin",
     "llama_FFN_UP_{L}_pos0_layer0_full_n5632_*.bin"),
    ("FFN_ACT_{L}", "FFN", "deep2_FFN_ACT_{L}_pos0_layer0_full_n5632_*.bin",
     "llama_FFN_ACT_{L}_pos0_layer0_full_n5632_*.bin"),
    ("FFN_DOWN_{L}", "FFN", "deep2_FFN_DOWN_{L}_pos0_layer0_full_n2048_*.bin",
     "llama_FFN_DOWN_{L}_pos0_layer0_full_n2048_*.bin"),
    ("LAYER{L}_OUT", "FFN", "deep2_LAYER{L}_OUT_pos0_layer0_full_n2048_*.bin",
     "llama_LAYER{L}_OUT_pos0_layer0_full_n2048_*.bin"),
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


def stats(a, b, abs_tol):
    n = min(len(a), len(b))
    s = 0.0
    mx = 0.0
    n_gt = 0
    for i in range(n):
        d = abs(a[i] - b[i])
        s += d * d
        if d > mx:
            mx = d
        if d > abs_tol:
            n_gt += 1
    l2b = math.sqrt(sum(x * x for x in b[:n]))
    rms = math.sqrt(s / n) if n else 0.0
    rel = rms / (l2b + 1e-30)
    return n, rms, rel, mx, n_gt


def seqnum(p):
    m = re.search(r"seq(\d+)", os.path.basename(p))
    return int(m.group(1)) if m else 999999


def pick(dirpath, pat):
    gs = glob.glob(os.path.join(dirpath, pat))
    if not gs:
        return None
    # Prefer earliest seq (primary fixture campaign; avoid later re-dumps).
    return sorted(gs, key=seqnum)[0]


def main():
    lines = []
    lines.append("GPU_PARITY_LAYER2_PLUS_C7402085_001.compare")
    lines.append("PAIR=stage_dump_layer2_plus_C7402085 vs stage_dump_gpu_fix")
    lines.append(
        "EXE=pin/rawr_attn_pre_o_fp16_product_wire.exe SHA256=C7402085… "
        "FORCE_VULKAN SPV=16292 Q4_KxQ8_K + PRE_O FP16 RT product-wire"
    )
    lines.append("MATERIAL_IF=(maxAbs>ABS_TOL) OR (rel_rms>REL_TOL)")
    lines.append("PARENT=GPU_PARITY_ATTN_PRE_O_FP16_PRODUCT_WIRE_001 (layer0+1 NONE)")
    lines.append(f"ASOF={datetime.now().isoformat(timespec='seconds')}")
    lines.append("SCAN_LAYERS=2..21 STAGE_DUMP_MAX_LAYER=21")

    first_mat = None
    first_mat_mx = None
    first_mat_rel = None
    scanned_layers = []
    missing_rows = 0
    compared_rows = 0

    # Stop at first MATERIAL but still record that layer's remaining probe
    # only until first hit (fail-closed first-diverge isolate).
    stop_after_material = True

    for L in range(2, 22):
        layer_had_compare = False
        layer_first = None
        for name_t, cls, gpat_t, rpat_t in PER_LAYER:
            name = name_t.replace("{L}", str(L))
            gpat = gpat_t.replace("{L}", str(L))
            rpat = rpat_t.replace("{L}", str(L))
            abs_tol, rel_tol = TOL[cls]
            gp = pick(gpu, gpat)
            rp = pick(ref, rpat)
            if not gp or not rp:
                # Q/V often absent as llama_* for L>=2 — note and continue.
                if name.startswith("Q_PRE_ROPE_") or name.startswith("V_"):
                    lines.append(
                        f"{name}: SKIP_REF_ABSENT g={bool(gp)} r={bool(rp)} class={cls}"
                    )
                    missing_rows += 1
                    continue
                lines.append(f"{name}: MISSING g={bool(gp)} r={bool(rp)} class={cls}")
                missing_rows += 1
                continue
            a, ra = load(gp)
            b, rb = load(rp)
            n, rms, rel, mx, n_gt = stats(a, b, abs_tol)
            fg, fr = fnv(ra), fnv(rb)
            material = (mx > abs_tol) or (rel > rel_tol)
            if fg == fr:
                kind = "EXACT"
            elif material:
                kind = "MATERIAL_DIVERGENCE"
            else:
                kind = "BITWISE_DIFF"
            lines.append(
                f"{name}: class={cls} kind={kind} maxAbs={mx:.6e} rel_rms={rel:.6e} "
                f"n_gt_abs={n_gt}/{n} abs_tol={abs_tol:g} rel_tol={rel_tol:g} "
                f"gpu_fnv={fg} ref_fnv={fr} gpu={os.path.basename(gp)} "
                f"ref={os.path.basename(rp)}"
            )
            compared_rows += 1
            layer_had_compare = True
            if material and layer_first is None:
                layer_first = (name, mx, rel)
            if material and first_mat is None:
                first_mat = name
                first_mat_mx = mx
                first_mat_rel = rel
                if stop_after_material:
                    # Finish remaining tensors on this layer only, then stop.
                    pass
        if layer_had_compare:
            scanned_layers.append(L)
        if first_mat is not None and stop_after_material:
            # After completing the layer that produced first MATERIAL, halt.
            break

    lines.append(f"COMPARED_ROWS={compared_rows}")
    lines.append(f"MISSING_OR_SKIP_ROWS={missing_rows}")
    lines.append(
        "SCANNED_LAYERS="
        + (",".join(str(x) for x in scanned_layers) if scanned_layers else "NONE")
    )
    if first_mat:
        lines.append(f"FIRST_MATERIAL_LAYER2_PLUS={first_mat}")
        lines.append(f"FIRST_MATERIAL_MAXABS={first_mat_mx:.6e}")
        lines.append(f"FIRST_MATERIAL_REL_RMS={first_mat_rel:.6e}")
        lines.append(f"NEXT_MATERIAL={first_mat}")
    else:
        lines.append("FIRST_MATERIAL_LAYER2_PLUS=NONE")
        lines.append("FIRST_MATERIAL_MAXABS=n/a")
        lines.append("FIRST_MATERIAL_REL_RMS=n/a")
        max_scanned = scanned_layers[-1] if scanned_layers else "NONE"
        lines.append(
            f"NEXT_MATERIAL=NONE (layer2..{max_scanned} scanned under class tol; "
            "not MATCH_PASS)"
        )
    lines.append("MATCH_PASS=0")
    lines.append("PROMOTE=0")
    lines.append("TIP_CLIMB=HOLD")
    lines.append("INVENT_PASS=0")
    lines.append("TIP_BIND=6754616E")
    lines.append("CLI_BOARD_TIP_PIN=15A119D1")

    text = "\n".join(lines) + "\n"
    out_ev = os.path.join(ev, "GPU_PARITY_LAYER2_PLUS_C7402085_001.compare.txt")
    out_seal = os.path.join(seal_gpu, "GPU_PARITY_LAYER2_PLUS_C7402085_001.compare.txt")
    for p in (out_ev, out_seal):
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        print("WROTE", p)
    print(text)
    return 0 if compared_rows > 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
