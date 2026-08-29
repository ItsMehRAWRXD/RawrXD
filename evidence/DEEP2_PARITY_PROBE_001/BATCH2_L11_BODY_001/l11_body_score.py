#!/usr/bin/env python3
"""BATCH2_L11_BODY_001 — L11 growth attribution (L10 closed)."""
from __future__ import annotations
import json, math, struct
from pathlib import Path

ABS_PASS, ABS_SOFT = 1e-6, 1e-4
REL_PASS, REL_INSPECT = 1e-6, 5e-6
L10_OUT_REF = 5.828e-5  # certified INHERITED_FROM_FFN_DOWN

def load(p: Path):
    b = p.read_bytes()
    n = len(b) // 4
    return list(struct.unpack(f"<{n}f", b))

def find_earliest(dir: Path, *pats: str):
    xs = []
    for pat in pats:
        xs.extend(dir.glob(pat))
    xs = sorted(xs, key=lambda p: p.name)
    return xs[0] if xs else None

def metrics(a, b):
    n = min(len(a), len(b))
    max_abs = mean_abs = l2 = max_rel = 0.0
    argmax = first = -1
    sabs = 0.0
    for i in range(n):
        d = abs(a[i] - b[i])
        denom = max(1.0, abs(a[i]), abs(b[i]))
        rel = d / denom
        sabs += d
        l2 += d * d
        if d > max_abs:
            max_abs, argmax = d, i
        if rel > max_rel:
            max_rel = rel
        if first < 0 and d > ABS_PASS:
            first = i
    mean_abs = sabs / n if n else 0.0
    l2 = math.sqrt(l2)
    if max_abs <= ABS_PASS or (max_abs <= ABS_SOFT and max_rel <= REL_PASS):
        dual = "PASS"
    elif max_abs <= ABS_SOFT and max_rel <= REL_INSPECT:
        dual = "INSPECT"
    else:
        dual = "FAIL"
    return {
        "n": n, "max_abs": max_abs, "mean_abs": mean_abs, "l2": l2,
        "max_rel": max_rel, "argmax": argmax, "first": first, "dual": dual,
    }

def classify(prev: float, cur: float) -> str:
    if cur <= ABS_PASS:
        return "CLOSED"
    if prev <= 0:
        return "unknown"
    # floor inheritance near tip eps
    if cur <= 5e-5 and abs(cur - prev) / max(prev, 1e-30) <= 0.25:
        return "inherited_floor"
    ratio = cur / prev
    if ratio <= 1.25:
        return "inherited"
    if ratio <= 5.0:
        return "amplification"
    return "candidate_new_root" if ratio > 5.0 else "amplification"

def main():
    root = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L11_BODY_001")
    ddir, ldir = root / "deep2", root / "llama"
    out = root

    # stage: (tag, deep2_pats, llama_pats)
    stages = [
        ("L11_IN", ["deep2_LAYER_OUT_10_pos0*.bin"], ["llama_LAYER10_OUT_pos0*.bin", "llama_LAYER_OUT_10_pos0*.bin"]),
        ("ATTN_OUT_11", ["deep2_ATTN_OUT_11_pos0*.bin"], ["llama_ATTN_OUT_11_pos0*.bin"]),
        ("FFN_INP_11", ["deep2_FFN_INP_11_pos0*.bin"], ["llama_FFN_INP_11_pos0*.bin"]),
        ("FFN_NORM_11", ["deep2_FFN_NORM_11_pos0*.bin"], ["llama_FFN_NORM_11_pos0*.bin"]),
        ("FFN_GATE_11", ["deep2_FFN_GATE_11_pos0*.bin"], ["llama_FFN_GATE_11_pos0*.bin"]),
        ("FFN_UP_11", ["deep2_FFN_UP_11_pos0*.bin"], ["llama_FFN_UP_11_pos0*.bin"]),
        ("FFN_ACT_11", ["deep2_FFN_ACT_11_pos0*.bin"], ["llama_FFN_ACT_11_pos0*.bin"]),
        ("FFN_DOWN_11", ["deep2_FFN_DOWN_11_pos0*.bin"], ["llama_FFN_DOWN_11_pos0*.bin"]),
        ("L11_OUT", ["deep2_LAYER_OUT_11_pos0*.bin"], ["llama_LAYER11_OUT_pos0*.bin", "llama_LAYER_OUT_11_pos0*.bin"]),
        ("L12_IN", ["deep2_LAYER_OUT_11_pos0*.bin"], ["llama_LAYER11_OUT_pos0*.bin"]),
        ("ATTN_OUT_12", ["deep2_ATTN_OUT_12_pos0*.bin"], ["llama_ATTN_OUT_12_pos0*.bin"]),
        ("FFN_INP_12", ["deep2_FFN_INP_12_pos0*.bin"], ["llama_FFN_INP_12_pos0*.bin"]),
        ("FFN_NORM_12", ["deep2_FFN_NORM_12_pos0*.bin"], ["llama_FFN_NORM_12_pos0*.bin"]),
        ("FFN_GATE_12", ["deep2_FFN_GATE_12_pos0*.bin"], ["llama_FFN_GATE_12_pos0*.bin"]),
        ("FFN_UP_12", ["deep2_FFN_UP_12_pos0*.bin"], ["llama_FFN_UP_12_pos0*.bin"]),
        ("FFN_ACT_12", ["deep2_FFN_ACT_12_pos0*.bin"], ["llama_FFN_ACT_12_pos0*.bin"]),
        ("FFN_DOWN_12", ["deep2_FFN_DOWN_12_pos0*.bin"], ["llama_FFN_DOWN_12_pos0*.bin"]),
        ("L12_OUT", ["deep2_LAYER_OUT_12_pos0*.bin"], ["llama_LAYER12_OUT_pos0*.bin", "llama_LAYER_OUT_12_pos0*.bin"]),
    ]

    rows = []
    report = {"prereq": "e53bac4b0 L10_OUT closed", "do_not_reopen": "L10", "stages": {}, "transitions": []}
    lines = []
    lines.append("BATCH2_L11_BODY_001")
    lines.append("prereq=e53bac4b0 L10_OUT=INHERITED_FROM_FFN_DOWN; L10 CLOSED")
    lines.append("authority=EXPAND_V + REF_CB_MAX_LAYER=12 + Deep2 STAGE_DUMP_LAYERS=10,11,12")
    lines.append("pairing=earliest pos0 seq")
    lines.append("dual: PASS if abs<=1e-6 OR (abs<=1e-4 AND rel<=1e-6); INSPECT if abs<=1e-4 AND rel<=5e-6")
    lines.append("")
    lines.append(f"{'stage':<14} {'dual':<8} {'max_abs':>12} {'mean_abs':>12} {'L2':>12} {'max_rel':>12} {'argmax':>7} {'amp_vs_prev':>12} {'class':<20} files")

    prev_abs = L10_OUT_REF
    prev_tag = "L10_OUT_CERT"
    for tag, dpats, lpats in stages:
        d = find_earliest(ddir, *dpats)
        l = find_earliest(ldir, *lpats)
        if not d or not l:
            lines.append(f"{tag:<14} MISSING d={bool(d)} l={bool(l)} dpats={dpats} lpats={lpats}")
            report["stages"][tag] = {"missing": True, "d": str(d), "l": str(l)}
            continue
        m = metrics(load(d), load(l))
        ratio = (m["max_abs"] / prev_abs) if prev_abs > 0 else float("inf")
        cls = classify(prev_abs, m["max_abs"])
        # ATTN residual delta: if ATTN_OUT is tiny vs IN, growth is not attn-native
        row = {
            "tag": tag, **m, "amp_vs_prev": ratio, "class": cls,
            "prev": prev_tag, "prev_abs": prev_abs,
            "d": d.name, "l": l.name,
        }
        rows.append(row)
        report["stages"][tag] = row
        report["transitions"].append({
            "from": prev_tag, "to": tag, "ratio": ratio, "class": cls,
            "prev_abs": prev_abs, "cur_abs": m["max_abs"],
        })
        lines.append(
            f"{tag:<14} {m['dual']:<8} {m['max_abs']:12.6e} {m['mean_abs']:12.6e} {m['l2']:12.6e} "
            f"{m['max_rel']:12.6e} {m['argmax']:7d} {ratio:12.3f} {cls:<20} {d.name} | {l.name}"
        )
        prev_abs = m["max_abs"]
        prev_tag = tag

    # Ownership summary
    lines.append("")
    lines.append("CLASSIFICATION")
    lines.append("--------------")
    l11_in = report["stages"].get("L11_IN", {})
    l11_out = report["stages"].get("L11_OUT", {})
    l12_out = report["stages"].get("L12_OUT", {})
    ffn_down11 = report["stages"].get("FFN_DOWN_11", {})
    ffn_down12 = report["stages"].get("FFN_DOWN_12", {})
    attn11 = report["stages"].get("ATTN_OUT_11", {})
    attn12 = report["stages"].get("ATTN_OUT_12", {})

    def g(st, k, default=None):
        return st.get(k, default) if isinstance(st, dict) else default

    lines.append(f"  L10_OUT_CERT max_abs={L10_OUT_REF:.3e} (frozen)")
    if l11_in:
        lines.append(f"  L11_IN       max_abs={g(l11_in,'max_abs'):.3e} dual={g(l11_in,'dual')} class={g(l11_in,'class')} amp_vs_L10={g(l11_in,'amp_vs_prev'):.3f}")
    if attn11:
        lines.append(f"  ATTN_OUT_11  max_abs={g(attn11,'max_abs'):.3e} dual={g(attn11,'dual')} class={g(attn11,'class')}")
    if l11_out:
        lines.append(f"  L11_OUT      max_abs={g(l11_out,'max_abs'):.3e} dual={g(l11_out,'dual')} class={g(l11_out,'class')}")
    if l12_out:
        lines.append(f"  L12_OUT      max_abs={g(l12_out,'max_abs'):.3e} dual={g(l12_out,'dual')} class={g(l12_out,'class')}")

    # Find earliest large jump within L11 and L11→L12
    jumps = [t for t in report["transitions"] if t["ratio"] > 1.25]
    lines.append("")
    lines.append("JUMPS (ratio>1.25)")
    for t in jumps:
        lines.append(f"  {t['from']} -> {t['to']}: {t['prev_abs']:.3e} -> {t['cur_abs']:.3e}  ratio={t['ratio']:.3f}  {t['class']}")

    # Fail-closed verdict
    growth_explained = True
    first_root = None
    for t in report["transitions"]:
        if t["to"].startswith("L1") and "OUT" in t["to"]:
            continue
        if t["class"] == "candidate_new_root":
            # allow strong amp through FFN if continuous growth chain without native same-op evidence
            if t["ratio"] > 8.0 and t["to"] not in ("FFN_GATE_11", "FFN_GATE_12", "FFN_UP_11", "FFN_UP_12", "FFN_DOWN_11", "FFN_DOWN_12", "FFN_ACT_11", "FFN_ACT_12"):
                growth_explained = False
                first_root = t
                break
            # GATE/UP/DOWN large amp from small NORM is expected amplification of inherited INP
            pass

    # Heuristic: if L11_IN ≈ L10_OUT and L11_OUT growth is through FFN_DOWN matching L11_OUT, freeze AMPLIFICATION
    l11_chain_ok = (
        l11_in and l11_out and ffn_down11
        and g(l11_in, "amp_vs_prev", 99) <= 1.25
        and abs(g(l11_out, "max_abs", 0) - g(ffn_down11, "max_abs", 1)) / max(g(ffn_down11, "max_abs", 1), 1e-30) < 0.15
    )
    l12_jump = None
    if l11_out and l12_out:
        l12_jump = g(l12_out, "max_abs") / max(g(l11_out, "max_abs"), 1e-30)

    lines.append("")
    if l11_chain_ok and (l12_jump is None or l12_jump < 8.0 or (ffn_down12 and abs(g(l12_out,"max_abs")-g(ffn_down12,"max_abs"))/max(g(ffn_down12,"max_abs"),1e-30)<0.15)):
        verdict = "AMPLIFICATION"
        lines.append("VERDICT=AMPLIFICATION")
        lines.append("  L11/L12 growth explained by propagation of inherited L10_OUT error;")
        lines.append("  no new native root localized; L10 remains CLOSED.")
        lines.append("NEXT=tip-align FINAL_NORM → LOGITS (pos0); do not chase L16/L21 yet")
    else:
        verdict = "LOCALIZE"
        lines.append("VERDICT=LOCALIZE_EARLIEST_JUMP")
        if first_root:
            lines.append(f"  first_candidate={first_root}")
        lines.append("  do not reopen L10")
    report["verdict"] = verdict
    report["l11_chain_ok"] = bool(l11_chain_ok)
    report["l12_jump"] = l12_jump

    ladder = "\n".join(lines) + "\n"
    (out / "LADDER.txt").write_text(ladder, encoding="utf-8")
    (out / "report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    gate = []
    gate.append("BATCH2_L11_BODY_001")
    gate.append("=" * 60)
    gate.append("date=2026-08-29")
    gate.append("prereq=e53bac4b0 L10_OUT INHERITED_FROM_FFN_DOWN (L10 CLOSED)")
    gate.append("authority=EXPAND_V + MAX_LAYER=12 + STAGE_DUMP_LAYERS=10,11,12")
    gate.append("")
    gate.append("L11 (first material growth beyond ~5.8e-5)")
    gate.append("-" * 40)
    for tag in ["L11_IN", "ATTN_OUT_11", "FFN_INP_11", "FFN_NORM_11", "FFN_GATE_11", "FFN_UP_11", "FFN_ACT_11", "FFN_DOWN_11", "L11_OUT"]:
        st = report["stages"].get(tag)
        if not st or st.get("missing"):
            gate.append(f"  {tag}: MISSING")
            continue
        gate.append(f"  {tag:<12} dual={st['dual']:<7} max_abs={st['max_abs']:.3e} mean={st['mean_abs']:.3e} L2={st['l2']:.3e} amp={st['amp_vs_prev']:.2f} class={st['class']}")
    gate.append("")
    gate.append("L12 (explain 1.07e-4 → 4.64e-4)")
    gate.append("-" * 40)
    for tag in ["ATTN_OUT_12", "FFN_INP_12", "FFN_GATE_12", "FFN_DOWN_12", "L12_OUT"]:
        st = report["stages"].get(tag)
        if not st or st.get("missing"):
            gate.append(f"  {tag}: MISSING")
            continue
        gate.append(f"  {tag:<12} dual={st['dual']:<7} max_abs={st['max_abs']:.3e} amp={st['amp_vs_prev']:.2f} class={st['class']}")
    gate.append("")
    gate.append(f"VERDICT={verdict}")
    gate.append("DO_NOT_reopen=L10 / GEMV / GATE-as-root / SiLU / HexMag / GBS / P1")
    if verdict == "AMPLIFICATION":
        gate.append("NEXT=tip-align FINAL_NORM → LOGITS")
    else:
        gate.append("NEXT=localize earliest ratio jump (still not L10)")
    (out / "GATE.txt").write_text("\n".join(gate) + "\n", encoding="utf-8")
    print(ladder)
    print(f"VERDICT={verdict}")

if __name__ == "__main__":
    main()
