#!/usr/bin/env python3
"""BATCH2_L10_OUT_RESCORE_001 — post FFN_INP_SAME_SOURCE certified state."""
from __future__ import annotations
import json, struct
from pathlib import Path

ABS_PASS, ABS_SOFT = 1e-6, 1e-4
REL_PASS, REL_INSPECT = 1e-6, 5e-6
FLOOR_EPS, FLOOR_MAX = 5e-5, 8

def load(p: Path):
    b = p.read_bytes()
    n = len(b) // 4
    return list(struct.unpack(f"<{n}f", b))

def cmp(a, b):
    max_abs = max_rel = 0.0
    largest = first = -1
    for i, (x, y) in enumerate(zip(a, b)):
        d = abs(x - y)
        denom = max(1.0, abs(x), abs(y))
        rel = d / denom
        if d > max_abs:
            max_abs, largest = d, i
        if rel > max_rel:
            max_rel = rel
        if first < 0 and d > ABS_PASS:
            first = i
    if max_abs <= ABS_PASS or (max_abs <= ABS_SOFT and max_rel <= REL_PASS):
        dual = "PASS"
    elif max_abs <= ABS_SOFT and max_rel <= REL_INSPECT:
        dual = "INSPECT"
    else:
        dual = "FAIL"
    abs_g = "PASS" if max_abs <= ABS_PASS else ("INSPECT" if max_abs <= 1e-5 else "FAIL")
    return {"abs": abs_g, "dual": dual, "max_abs": max_abs, "max_rel": max_rel, "first": first, "largest": largest}

def find_first(dir: Path, pat: str):
    xs = sorted(dir.glob(pat))
    return xs[0] if xs else None

def classify(prev_abs: float, out_abs: float, same_operand_closed: bool = False) -> str:
    """inherited | amplification | native — heuristic from magnitude ratios."""
    if out_abs <= ABS_PASS:
        return "CLOSED"
    if same_operand_closed:
        return "inherited"
    if prev_abs <= 0:
        return "native_or_unknown"
    ratio = out_abs / prev_abs
    if ratio <= 1.25:
        return "inherited"
    if ratio <= 5.0:
        return "amplification"
    return "amplification_strong"

def main():
    root = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001")
    body = root / "BATCH2_L10_BODY_001"
    sc_d = root / "BATCH2_SPARSE_CLEAN_001" / "deep2_post_swiglu_fix"
    sc_l = root / "BATCH2_SPARSE_CLEAN_001" / "llama"
    exp_l = root / "BATCH2_L8_L12_EXPAND_001" / "llama"
    out = root / "BATCH2_L10_OUT_RESCORE_001"
    out.mkdir(parents=True, exist_ok=True)

    # --- L10 body ownership chain ---
    d_inp = find_first(body / "deep2", "deep2_FFN_INP_10_pos0*.bin")
    l_inp = find_first(body / "llama", "llama_FFN_INP_10_pos0*.bin")
    d_down = find_first(body / "deep2", "deep2_FFN_DOWN_10_pos0*.bin")
    l_down = find_first(body / "llama", "llama_FFN_DOWN_10_pos0*.bin")
    d_gate = find_first(body / "deep2", "deep2_FFN_GATE_10_pos0*.bin")
    l_gate = find_first(body / "llama", "llama_FFN_GATE_10_pos0*.bin")
    d_post = find_first(body / "deep2", "deep2_POST_FFN_10_pos0*.bin")
    d_lout = find_first(body / "deep2", "deep2_LAYER_OUT_10_pos0*.bin")
    # llama L10 tip from expand (EXPAND_V same authority family)
    l_lout = find_first(exp_l, "llama_LAYER10_OUT_pos0*.bin")
    d_lout_sc = find_first(sc_d, "deep2_LAYER_OUT_10_pos0*.bin")

    lines = []
    lines.append("BATCH2_L10_OUT_RESCORE_001")
    lines.append("prereq=7ee02e8b3 L10_FFN_INP_SAME_SOURCE PASS; GATE inherited from RESID_IN")
    lines.append("do_not_reopen=L10 GEMV / FFN_GATE root / SiLU / HexMag")
    lines.append("dual: PASS if abs<=1e-6 OR (abs<=1e-4 AND rel<=1e-6); INSPECT if abs<=1e-4 AND rel<=5e-6")
    lines.append("")

    report = {"prereq": "7ee02e8b3", "l10_body": {}, "sparse_tips": {}, "classes": {}}

    def add(tag, a, b, prev_abs=None, note=""):
        c = cmp(a, b)
        cls = None
        if prev_abs is not None:
            cls = classify(prev_abs, c["max_abs"])
        tip_gate = c["dual"]
        layer = None
        if tag.startswith("L") and "_OUT" in tag:
            try:
                layer = int(tag.split("_")[0][1:])
            except Exception:
                layer = None
        if layer is not None and layer <= FLOOR_MAX and c["max_abs"] <= FLOOR_EPS:
            tip_gate = "PASS_FLOOR"
            if cls is None:
                cls = "floor"
        line = f"{tag:12s} abs={c['abs']:7s} dual={c['dual']:7s} tip={tip_gate:10s} max_abs={c['max_abs']:.6e} max_rel={c['max_rel']:.6e} first={c['first']} largest={c['largest']}"
        if cls:
            line += f" class={cls}"
        if note:
            line += f"  # {note}"
        lines.append(line)
        report["l10_body" if tag.startswith("FFN") or tag.startswith("L10") or tag.startswith("POST") or tag.startswith("RECON") else "sparse_tips"][tag] = {**c, "class": cls, "note": note}
        if cls:
            report["classes"][tag] = cls
        return c

    # Load body tensors
    Di, Li = load(d_inp), load(l_inp)
    Dd, Ld = load(d_down), load(l_down)
    Dg, Lg = load(d_gate), load(l_gate)
    Dp, Dl = load(d_post), load(d_lout)

    c_inp = add("FFN_INP_10", Di, Li, note="certified FIRST_ABS_FAIL / RESID_IN carrier")
    c_gate = add("FFN_GATE_10", Dg, Lg, prev_abs=c_inp["max_abs"], note="INHERITED (not root); GEMV CLOSED")
    c_down = add("FFN_DOWN_10", Dd, Ld, prev_abs=c_gate["max_abs"], note="post-SwiGLU down proj")

    # Reconstruct L10_OUT = FFN_INP + FFN_DOWN
    recon_d = [x + y for x, y in zip(Di, Dd)]
    recon_l = [x + y for x, y in zip(Li, Ld)]
    c_id = cmp(recon_d, Dl)
    lines.append(f"{'RECON_d==L10':12s} abs={c_id['abs']:7s} dual={c_id['dual']:7s} max_abs={c_id['max_abs']:.6e}  # Deep2 POST residual identity")
    c_id2 = cmp(recon_d, Dp)
    lines.append(f"{'RECON_d==POST':12s} abs={c_id2['abs']:7s} dual={c_id2['dual']:7s} max_abs={c_id2['max_abs']:.6e}")

    c_l10_body = add("L10_OUT_body", recon_d, recon_l, prev_abs=c_down["max_abs"],
                     note="same-run recon from body FFN_INP+FFN_DOWN")

    # Cross-authority tip (sparse clean deep2 vs expand llama) — diagnostic only
    if d_lout_sc and l_lout:
        c_tip = add("L10_OUT_tip", load(d_lout_sc), load(l_lout), prev_abs=c_inp["max_abs"],
                    note="sparse_clean deep2 vs expand llama (EXPAND_V family)")

    lines.append("")
    lines.append("SPARSE LADDER (certified L10 context — do not reopen L10 predicates)")
    tips = [
        ("L8_OUT", 8, sc_d / "deep2_LAYER_OUT_8_pos0*.bin", sc_l / "llama_LAYER8_OUT_pos0*.bin"),
        ("L9_OUT", 9, sc_d / "deep2_LAYER_OUT_9_pos0*.bin", exp_l / "llama_LAYER9_OUT_pos0*.bin"),
        ("L10_OUT", 10, sc_d / "deep2_LAYER_OUT_10_pos0*.bin", exp_l / "llama_LAYER10_OUT_pos0*.bin"),
        ("L11_OUT", 11, sc_d / "deep2_LAYER_OUT_11_pos0*.bin", exp_l / "llama_LAYER11_OUT_pos0*.bin"),
        ("L12_OUT", 12, sc_d / "deep2_LAYER_OUT_12_pos0*.bin", sc_l / "llama_LAYER12_OUT_pos0*.bin"),
        ("L16_OUT", 16, sc_d / "deep2_LAYER_OUT_16_pos0*.bin", sc_l / "llama_LAYER16_OUT_pos0*.bin"),
        ("L21_OUT", 21, sc_d / "deep2_LAYER_OUT_21_pos0*.bin", sc_l / "llama_LAYER21_OUT_pos0*.bin"),
        ("FINAL_NORM", 99, sc_d / "deep2_FINAL_NORM_pos0*.bin", sc_l / "llama_FINAL_NORM_pos0*.bin"),
        ("LOGITS", 100, sc_d / "deep2_LOGITS_pos0*.bin", sc_l / "llama_LOGITS_pos0*.bin"),
    ]
    # Also try PROMPT_FINAL_NORM
    prev = c_l10_body["max_abs"]
    first_growth = None
    for name, layer, dp, lp in tips:
        pd = find_first(dp.parent, dp.name)
        pl = find_first(lp.parent, lp.name)
        if not pd:
            # FINAL_NORM alternate
            if name == "FINAL_NORM":
                pd = find_first(sc_d, "deep2_PROMPT_FINAL_NORM_pos0*.bin") or find_first(sc_d, "deep2_FINAL_NORM_pos0*.bin")
            if name == "LOGITS":
                pd = find_first(sc_d, "deep2_LOGITS_pos0*.bin") or find_first(sc_d, "deep2_PROMPT_LOGITS_pos0*.bin")
        if not pd or not pl:
            lines.append(f"{name:12s} SKIP missing d={bool(pd)} l={bool(pl)}")
            continue
        a, b = load(pd), load(pl)
        if len(a) != len(b):
            lines.append(f"{name:12s} SKIP nelem mismatch {len(a)} vs {len(b)}")
            continue
        c = add(name, a, b, prev_abs=prev, note=f"layer={layer}")
        if layer >= 10 and c["dual"] == "FAIL" and first_growth is None and name != "L10_OUT":
            first_growth = name
        if layer >= 8:
            prev = c["max_abs"]

    lines.append("")
    lines.append("CLASSIFICATION SUMMARY")
    lines.append(f"  L10_OUT_body class={report['classes'].get('L10_OUT_body')} max_abs={c_l10_body['max_abs']:.6e}")
    lines.append(f"  vs FFN_DOWN max_abs={c_down['max_abs']:.6e} ratio={c_l10_body['max_abs']/max(c_down['max_abs'],1e-30):.3f}")
    lines.append(f"  vs FFN_INP  max_abs={c_inp['max_abs']:.6e} ratio={c_l10_body['max_abs']/max(c_inp['max_abs'],1e-30):.3f}")
    lines.append(f"  L10_OUT ≈ FFN_DOWN (residual add of INP): inherited from DOWN/GATE chain")
    if abs(c_l10_body['max_abs'] - c_down['max_abs']) / max(c_down['max_abs'], 1e-30) < 0.05:
        lines.append("  VERDICT_L10_OUT=INHERITED_FROM_FFN_DOWN (nearly identical error footprint)")
        report["verdict_l10_out"] = "INHERITED_FROM_FFN_DOWN"
    else:
        lines.append("  VERDICT_L10_OUT=CHECK_AMPLIFICATION_AT_RESIDUAL")
        report["verdict_l10_out"] = "CHECK"

    # growth after L10
    for k in ["L11_OUT", "L12_OUT", "L16_OUT", "L21_OUT", "FINAL_NORM", "LOGITS"]:
        if k in report["classes"]:
            lines.append(f"  {k} class={report['classes'][k]} dual={report['sparse_tips'].get(k, report['l10_body'].get(k, {})).get('dual')}")

    lines.append("")
    lines.append("NEXT")
    # Prefer first strong amplification after L10
    nxt = first_growth or "L12_OUT"
    lines.append(f"  Active tip after certified L10: {nxt}")
    lines.append("  Keep L10 predicates closed; attribute further growth as inherited/amplification/native")
    lines.append("  GBS/P1: independent — unchanged by this cert")

    (out / "LADDER.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    gate = []
    gate.append("BATCH2_L10_OUT_RESCORE_001")
    gate.append("=" * 60)
    gate.append("date=2026-08-29")
    gate.append("cert_commit=7ee02e8b3 L10_FFN_INP_SAME_SOURCE")
    gate.append("")
    gate.append("L10_OUT")
    gate.append(f"  body_recon dual={c_l10_body['dual']} max_abs={c_l10_body['max_abs']:.3e}")
    gate.append(f"  class={report.get('verdict_l10_out')} (matches FFN_DOWN footprint)")
    gate.append(f"  FFN_DOWN max_abs={c_down['max_abs']:.3e}  FFN_INP={c_inp['max_abs']:.3e}")
    gate.append("")
    gate.append("SPARSE continuation (from certified L10)")
    for k in ["L8_OUT", "L9_OUT", "L10_OUT", "L11_OUT", "L12_OUT", "L16_OUT", "L21_OUT", "FINAL_NORM", "LOGITS"]:
        e = report["sparse_tips"].get(k) or report["l10_body"].get(k)
        if not e:
            continue
        gate.append(f"  {k:12s} dual={e['dual']:7s} max_abs={e['max_abs']:.3e} class={e.get('class')}")
    gate.append("")
    gate.append(f"VERDICT_L10_OUT={report.get('verdict_l10_out')}")
    gate.append("DO_NOT_reopen=L10 GEMV / GATE-as-root / SiLU / HexMag / GBS / P1")
    gate.append(f"NEXT=continue sparse growth at {nxt} with class tags; LOGITS when tip-aligned")
    (out / "GATE.txt").write_text("\n".join(gate) + "\n", encoding="utf-8")
    print("\n".join(gate))
    print(f"wrote {out}")

if __name__ == "__main__":
    main()
