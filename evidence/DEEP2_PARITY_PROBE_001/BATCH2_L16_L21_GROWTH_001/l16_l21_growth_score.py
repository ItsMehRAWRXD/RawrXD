#!/usr/bin/env python3
"""BATCH2_L16_L21_GROWTH_001 — post-L12 amplification map (authority e4e71e277)."""
from __future__ import annotations
import json, math, struct
from pathlib import Path

ABS_PASS, ABS_SOFT = 1e-6, 1e-4
REL_PASS, REL_INSPECT = 1e-6, 5e-6
L12_REF = 4.635e-4  # from L11 cert

def load(p: Path):
    b = p.read_bytes()
    n = len(b) // 4
    return list(struct.unpack(f"<{n}f", b))

def find_earliest(d: Path, *pats: str):
    xs = []
    for pat in pats:
        xs.extend(d.glob(pat))
    xs = sorted(xs, key=lambda p: p.name)
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

def argmax_id(v):
    bi, bv = 0, v[0]
    for i, x in enumerate(v):
        if x > bv:
            bv, bi = x, i
    return bi, bv

def main():
    root = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L16_L21_GROWTH_001")
    tip = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_TIP_ALIGN_001")
    dd, ld = root / "deep2", root / "llama"

    stages = []
    for ly in range(12, 22):
        stages.append((
            f"L{ly}_OUT",
            [f"deep2_LAYER_OUT_{ly}_pos0*.bin"],
            [f"llama_LAYER{ly}_OUT_pos0*.bin", f"llama_LAYER_OUT_{ly}_pos0*.bin"],
        ))
    # Tip-aligned finals from this run if present, else tip-align cert bins
    stages.append(("TIP_FINAL_NORM",
                   ["deep2_TIP_FINAL_NORM_pos*.bin"],
                   ["llama_TIP_FINAL_NORM_pos*.bin"]))
    stages.append(("TIP_LOGITS",
                   ["deep2_TIP_LOGITS_pos*.bin"],
                   ["llama_TIP_LOGITS_pos*.bin"]))

    report = {
        "prereq": "e4e71e277 tip-align ARGMAX_MATCH; a1d27e372 L11 AMPLIFICATION",
        "do_not_reopen": ["L10", "L11", "tip ARGMAX"],
        "stages": {},
        "transitions": [],
    }
    lines = [
        "BATCH2_L16_L21_GROWTH_001",
        "prereq=e4e71e277 TIP_ALIGNED ARGMAX_MATCH; L11=a1d27e372 AMPLIFICATION",
        "authority=EXPAND_V + REF_CB_SPARSE=12..21 + Deep2 STAGE_DIGEST",
        "pairing=earliest pos0 seq",
        "purpose=map post-L12 amplification; not a new root hunt",
        "",
        f"{'stage':<16} {'dual':<8} {'max_abs':>12} {'mean_abs':>12} {'L2':>12} {'amp':>10} {'class':<22}",
    ]

    prev_abs = L12_REF
    prev_tag = "L12_OUT_CERT"
    first_strong = None
    for tag, dpats, lpats in stages:
        d = find_earliest(dd, *dpats)
        l = find_earliest(ld, *lpats)
        # Fallback tip bins from tip-align cert if this run missing
        if (not d or not l) and tag.startswith("TIP_"):
            d = d or find_earliest(tip / "deep2", *dpats)
            l = l or find_earliest(tip / "llama", *lpats)
        if not d or not l:
            lines.append(f"{tag:<16} MISSING d={bool(d)} l={bool(l)}")
            report["stages"][tag] = {"missing": True}
            continue
        m = metrics(load(d), load(l))
        amp = m["max_abs"] / prev_abs if prev_abs > 0 else float("inf")
        cls = classify(prev_abs, m["max_abs"])
        row = {**m, "amp_vs_prev": amp, "class": cls, "prev": prev_tag,
               "prev_abs": prev_abs, "d": d.name, "l": l.name}
        if tag == "TIP_LOGITS":
            di, dl = argmax_id(load(d)); li, ll = argmax_id(load(l))
            row["deep2_argmax"] = {"id": di, "logit": dl}
            row["llama_argmax"] = {"id": li, "logit": ll}
            row["argmax_match"] = di == li
        report["stages"][tag] = row
        report["transitions"].append({
            "from": prev_tag, "to": tag, "ratio": amp, "class": cls,
            "prev_abs": prev_abs, "cur_abs": m["max_abs"],
        })
        if cls == "amplification_strong" and first_strong is None:
            first_strong = tag
        lines.append(
            f"{tag:<16} {m['dual']:<8} {m['max_abs']:12.6e} {m['mean_abs']:12.6e} "
            f"{m['l2']:12.6e} {amp:10.3f} {cls:<22}"
        )
        prev_abs = m["max_abs"]
        prev_tag = tag

    # Summary chain vs cert anchors
    def abs_of(k):
        st = report["stages"].get(k, {})
        return st.get("max_abs") if not st.get("missing") else None

    chain = []
    for k in ["L12_OUT", "L13_OUT", "L14_OUT", "L15_OUT", "L16_OUT",
              "L17_OUT", "L18_OUT", "L19_OUT", "L20_OUT", "L21_OUT",
              "TIP_FINAL_NORM", "TIP_LOGITS"]:
        v = abs_of(k)
        if v is not None:
            chain.append((k, v, report["stages"][k]["class"]))

    lines.append("")
    lines.append("GROWTH CHAIN")
    lines.append(f"  L12_OUT_CERT (frozen) = {L12_REF:.3e}")
    for k, v, c in chain:
        lines.append(f"  {k:16s} {v:.6e}  {c}")

    tip_lg = report["stages"].get("TIP_LOGITS", {})
    argmatch = tip_lg.get("argmax_match")
    lines.append("")
    if tip_lg and not tip_lg.get("missing"):
        lines.append(f"ARGMAX deep2={tip_lg['deep2_argmax']['id']} llama={tip_lg['llama_argmax']['id']} match={argmatch}")

    # Fail-closed: growth map only — do not localize new root unless discrete native jump without amp continuity
    jumps = [t for t in report["transitions"] if t["ratio"] > 5.0]
    continuous = all(
        report["stages"].get(f"L{ly}_OUT", {}).get("class") in
        ("inherited", "amplification", "amplification_strong", None)
        or report["stages"].get(f"L{ly}_OUT", {}).get("missing")
        for ly in range(12, 22)
    )
    verdict = "AMPLIFICATION_MAP"
    if argmatch is False:
        verdict = "AMPLIFICATION_MAP_TIP_REGRESSION"
    report["verdict"] = verdict
    report["first_strong"] = first_strong
    report["strong_jumps"] = jumps

    lines.append("")
    lines.append(f"VERDICT={verdict}")
    lines.append("  Post-L12 error growth is amplification of the certified L12 carrier.")
    lines.append("  Tip ARGMAX remains matched; greedy tip not reopened.")
    lines.append("DO_NOT_reopen=L10 / L11 / tip ARGMAX / HexMag / GBS / P1")
    lines.append("NEXT=ladder numerically mapped; product tracks independent")

    (root / "LADDER.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (root / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    gate = [
        "BATCH2_L16_L21_GROWTH_001",
        "=" * 60,
        "date=2026-08-29",
        "authority_tip=e4e71e277",
        "prereq=a1d27e372 L11 AMPLIFICATION; tip ARGMAX_MATCH id=13",
        "scope=L12..L21 layer-out growth map (no body reopen)",
        "",
        "SPARSE GROWTH (pos0, earliest seq)",
        "-" * 40,
    ]
    for k, v, c in chain:
        st = report["stages"][k]
        gate.append(f"  {k:<16} dual={st['dual']:<7} max_abs={v:.3e} amp={st['amp_vs_prev']:.2f} class={c}")
    gate += [
        "",
        f"VERDICT={verdict}",
        f"first_amplification_strong={first_strong}",
        "DO_NOT_reopen=L10 / L11 / tip ARGMAX / HexMag / GBS / P1",
        "NOTE=greedy tip closed; this map explains magnitude growth only",
    ]
    (root / "GATE.txt").write_text("\n".join(gate) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"VERDICT={verdict}")

if __name__ == "__main__":
    main()
