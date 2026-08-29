#!/usr/bin/env python3
"""BATCH2_TIP_ALIGN_001 — tip-aligned FINAL_NORM / LOGITS (L11 authority a1d27e372)."""
from __future__ import annotations
import json, math, re, struct
from pathlib import Path

ABS_PASS, ABS_SOFT = 1e-6, 1e-4
REL_PASS, REL_INSPECT = 1e-6, 5e-6
L12_OUT_REF = 4.635e-4  # from L11 cert amplification chain

def load(p: Path):
    b = p.read_bytes()
    n = len(b) // 4
    return list(struct.unpack(f"<{n}f", b))

def find_earliest(d: Path, pat: str):
    xs = sorted(d.glob(pat))
    return xs[0] if xs else None

def metrics(a, b):
    n = min(len(a), len(b))
    max_abs = max_rel = l2 = sabs = 0.0
    argmax = first = -1
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
    l2 = math.sqrt(l2)
    mean_abs = sabs / n if n else 0.0
    if max_abs <= ABS_PASS or (max_abs <= ABS_SOFT and max_rel <= REL_PASS):
        dual = "PASS"
    elif max_abs <= ABS_SOFT and max_rel <= REL_INSPECT:
        dual = "INSPECT"
    else:
        dual = "FAIL"
    return {"n": n, "max_abs": max_abs, "mean_abs": mean_abs, "l2": l2,
            "max_rel": max_rel, "argmax": argmax, "first": first, "dual": dual}

def argmax_id(v):
    best_i, best = 0, v[0]
    for i, x in enumerate(v):
        if x > best:
            best, best_i = x, i
    return best_i, best

def parse_argmax(path: Path, side: str):
    text = path.read_text(encoding="utf-8", errors="replace")
    # last ARGMAX for side
    hits = re.findall(rf"side={side} key=ARGMAX pos=(\d+) id=(\d+) logit=([-+0-9.eE]+)", text)
    if hits:
        # First ARGMAX = tip (prefill); later may be decode mirrors
        pos, id_, logit = hits[0]
        return {"pos": int(pos), "id": int(id_), "logit": float(logit)}
    # llama REF_SELECTED
    m = re.search(r"REF_SELECTED_ID=(\d+)", text)
    if m:
        return {"pos": None, "id": int(m.group(1)), "logit": None}
    return None

def classify(prev, cur):
    if cur <= ABS_PASS:
        return "CLOSED"
    if prev <= 0:
        return "unknown"
    r = cur / prev
    if r <= 1.25:
        return "inherited"
    if r <= 5.0:
        return "amplification"
    return "amplification_strong"

def main():
    root = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_TIP_ALIGN_001")
    dd, ld = root / "deep2", root / "llama"

    pairs = [
        ("TIP_FINAL_NORM", "deep2_TIP_FINAL_NORM_pos*.bin", "llama_TIP_FINAL_NORM_pos*.bin"),
        ("TIP_FINAL_HIDDEN", "deep2_TIP_FINAL_HIDDEN_pos*.bin", "llama_TIP_FINAL_NORM_pos*.bin"),  # llama tip norm == hidden for logits
        ("TIP_LOGITS", "deep2_TIP_LOGITS_pos*.bin", "llama_TIP_LOGITS_pos*.bin"),
        # Non-authoritative mispair (document only)
        ("MISPAIR_FN_d0_l0", "deep2_FINAL_NORM_pos0*.bin", "llama_FINAL_NORM_pos0*.bin"),
        ("MISPAIR_LOG_d3_l0", "deep2_LOGITS_pos3*.bin", "llama_LOGITS_pos0*.bin"),
    ]

    report = {
        "prereq": "a1d27e372 L11 AMPLIFICATION",
        "authority": "EXPAND_V tip = last prompt token",
        "align_rule": {
            "deep2_TIP_FINAL_NORM": "pos=promptLen-1 (2)",
            "deep2_TIP_LOGITS": "filename pos=promptLen (3) but content=logits(last prompt hidden)",
            "llama_TIP_*": "sole/last prefill column; filename may say pos0 when tensor is tip-only",
        },
        "stages": {},
    }
    lines = []
    lines.append("BATCH2_TIP_ALIGN_001")
    lines.append("prereq=a1d27e372 L11/L12=AMPLIFICATION; L10 CLOSED")
    lines.append("align=TIP_* last-prompt hidden / first decode sample")
    lines.append("NOTE: deep2 TIP_LOGITS filename pos3 != llama TIP_LOGITS filename pos0; CONTENT is tip-aligned")
    lines.append("")

    prev = L12_OUT_REF
    for tag, dp, lp in pairs:
        d = find_earliest(dd, dp)
        l = find_earliest(ld, lp)
        if not d or not l:
            lines.append(f"{tag}: MISSING d={d} l={l}")
            report["stages"][tag] = {"missing": True}
            continue
        m = metrics(load(d), load(l))
        cls = classify(prev, m["max_abs"]) if tag.startswith("TIP_") else "diagnostic_mispair"
        amp = m["max_abs"] / prev if prev > 0 else None
        row = {**m, "class": cls, "amp_vs_prev": amp, "d": d.name, "l": l.name, "prev_abs": prev}
        if tag.startswith("TIP_LOGITS"):
            di, dl = argmax_id(load(d))
            li, ll = argmax_id(load(l))
            row["deep2_argmax"] = {"id": di, "logit": dl}
            row["llama_argmax"] = {"id": li, "logit": ll}
            row["argmax_match"] = di == li
        report["stages"][tag] = row
        lines.append(
            f"{tag:18s} dual={m['dual']:7s} max_abs={m['max_abs']:.6e} mean={m['mean_abs']:.6e} "
            f"L2={m['l2']:.6e} max_rel={m['max_rel']:.6e} argmax_i={m['argmax']} "
            f"amp={amp if amp is not None else float('nan'):.3f} class={cls}"
        )
        lines.append(f"  d={d.name}")
        lines.append(f"  l={l.name}")
        if tag.startswith("TIP_") and tag != "MISPAIR_FN_d0_l0":
            prev = m["max_abs"]

    d_arg = parse_argmax(root / "deep2.stdout.txt", "deep2")
    l_arg = parse_argmax(root / "llama.stdout.txt", "llama")
    report["stdout_argmax"] = {"deep2": d_arg, "llama": l_arg}

    tip_fn = report["stages"].get("TIP_FINAL_NORM", {})
    tip_lg = report["stages"].get("TIP_LOGITS", {})
    lines.append("")
    lines.append("ARGMAX")
    if tip_lg and not tip_lg.get("missing"):
        lines.append(f"  from bins: deep2 id={tip_lg['deep2_argmax']['id']} llama id={tip_lg['llama_argmax']['id']} match={tip_lg['argmax_match']}")
    lines.append(f"  from stdout: deep2={d_arg} llama={l_arg}")

    # Verdict
    aligned = bool(tip_fn) and not tip_fn.get("missing") and bool(tip_lg) and not tip_lg.get("missing")
    match = tip_lg.get("argmax_match") if tip_lg else False
    if aligned:
        verdict = "TIP_ALIGNED"
        if match:
            tip_gate = "ARGMAX_MATCH"
        else:
            tip_gate = "ARGMAX_MISMATCH"
        # growth class for tip vs L12
        tip_class = tip_lg.get("class", "unknown")
    else:
        verdict = "TIP_ALIGN_INCOMPLETE"
        tip_gate = "FAIL"
        tip_class = "unknown"

    report["verdict"] = verdict
    report["tip_gate"] = tip_gate
    report["tip_logits_class"] = tip_class

    lines.append("")
    lines.append(f"VERDICT={verdict}")
    lines.append(f"TIP_GATE={tip_gate}")
    lines.append(f"TIP_LOGITS_CLASS={tip_class}")
    lines.append("DO_NOT_reopen=L10 / L11 cert a1d27e372 / HexMag / GBS / P1")
    if tip_gate == "ARGMAX_MATCH":
        lines.append("NEXT=optional L16/L21 growth map OR freeze tip PASS and close numerical ladder for greedy-1")
    else:
        lines.append("NEXT=attribute tip mismatch to inherited amp vs native logits GEMV (same-hidden inject)")

    (root / "LADDER.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (root / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    gate = []
    gate.append("BATCH2_TIP_ALIGN_001")
    gate.append("=" * 60)
    gate.append("date=2026-08-29")
    gate.append("prereq=a1d27e372 L11 AMPLIFICATION (L10 CLOSED)")
    gate.append("authority=EXPAND_V; tip = last prompt token logits")
    gate.append("")
    gate.append("ALIGN RULE")
    gate.append("  deep2 TIP_FINAL_NORM @ pos2  <->  llama TIP_FINAL_NORM (tip column; file may say pos0)")
    gate.append("  deep2 TIP_LOGITS      @ pos3  <->  llama TIP_LOGITS (same tip content)")
    gate.append("  prior SKIP (deep2 LOGITS pos3 vs llama LOGITS pos0 without TIP_*) = NON-AUTHORITATIVE")
    gate.append("")
    if tip_fn and not tip_fn.get("missing"):
        gate.append(f"TIP_FINAL_NORM  dual={tip_fn['dual']} max_abs={tip_fn['max_abs']:.3e} class={tip_fn['class']}")
    if tip_lg and not tip_lg.get("missing"):
        gate.append(f"TIP_LOGITS      dual={tip_lg['dual']} max_abs={tip_lg['max_abs']:.3e} class={tip_lg['class']}")
        gate.append(f"ARGMAX          deep2={tip_lg['deep2_argmax']['id']} llama={tip_lg['llama_argmax']['id']} match={tip_lg['argmax_match']}")
    gate.append("")
    gate.append(f"VERDICT={verdict}")
    gate.append(f"TIP_GATE={tip_gate}")
    gate.append("DO_NOT_reopen=L10 / L11 / HexMag / GBS / P1")
    (root / "GATE.txt").write_text("\n".join(gate) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"VERDICT={verdict} TIP_GATE={tip_gate}")

if __name__ == "__main__":
    main()
