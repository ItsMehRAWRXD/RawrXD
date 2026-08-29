#!/usr/bin/env python3
"""Sparse tip re-score under dual abs/rel gate (post L2_OUT_LOC)."""
from __future__ import annotations

import json
import struct
from pathlib import Path

ABS_PASS, ABS_INSPECT, ABS_SOFT = 1e-6, 1e-5, 1e-4
REL_PASS, REL_INSPECT = 1e-6, 5e-6
# SPARSE_TIP_NUMERICAL_FLOOR_001: L0..8 inherited ULP floor (FFN_GATE_2 @5475).
# Do NOT apply this globally to L12+ growth.
FLOOR_EPS = 5.0e-5
FLOOR_MAX_LAYER = 8


def load(p: Path):
    b = p.read_bytes()
    n = len(b) // 4
    return list(struct.unpack(f"<{n}f", b))


def cmp(a, b):
    max_abs = 0.0
    max_rel = 0.0
    largest = -1
    first_abs = -1
    for i, (x, y) in enumerate(zip(a, b)):
        d = abs(x - y)
        denom = max(1.0, abs(x), abs(y))
        rel = d / denom
        if d > max_abs:
            max_abs = d
            largest = i
        if rel > max_rel:
            max_rel = rel
        if first_abs < 0 and d > ABS_PASS:
            first_abs = i
    if max_abs <= ABS_PASS:
        abs_g = "PASS"
    elif max_abs <= ABS_INSPECT:
        abs_g = "INSPECT"
    else:
        abs_g = "FAIL"
    if max_abs <= ABS_PASS or (max_abs <= ABS_SOFT and max_rel <= REL_PASS):
        dual = "PASS"
    elif max_abs <= ABS_INSPECT or (max_abs <= ABS_SOFT and max_rel <= REL_INSPECT):
        dual = "INSPECT"
    else:
        dual = "FAIL"
    return abs_g, dual, max_abs, max_rel, first_abs, largest


def find(dir: Path, pat: str):
    xs = sorted(dir.glob(pat))
    return xs[0] if xs else None


def main():
    sc = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_SPARSE_CLEAN_001")
    d2 = sc / "deep2_post_swiglu_fix"
    ll = sc / "llama"
    out = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_SPARSE_TIPS_DUAL_001")
    out.mkdir(parents=True, exist_ok=True)

    tips = [
        ("L2_OUT", 2, "deep2_LAYER_OUT_2_pos0*.bin", "llama_LAYER2_OUT_pos0*.bin"),
        ("L4_OUT", 4, "deep2_LAYER_OUT_4_pos0*.bin", "llama_LAYER4_OUT_pos0*.bin"),
        ("L8_OUT", 8, "deep2_LAYER_OUT_8_pos0*.bin", "llama_LAYER8_OUT_pos0*.bin"),
        ("L9_OUT", 9, "deep2_LAYER_OUT_9_pos0*.bin", "llama_LAYER9_OUT_pos0*.bin"),
        ("L10_OUT", 10, "deep2_LAYER_OUT_10_pos0*.bin", "llama_LAYER10_OUT_pos0*.bin"),
        ("L11_OUT", 11, "deep2_LAYER_OUT_11_pos0*.bin", "llama_LAYER11_OUT_pos0*.bin"),
        ("L12_OUT", 12, "deep2_LAYER_OUT_12_pos0*.bin", "llama_LAYER12_OUT_pos0*.bin"),
        ("L16_OUT", 16, "deep2_LAYER_OUT_16_pos0*.bin", "llama_LAYER16_OUT_pos0*.bin"),
        ("L21_OUT", 21, "deep2_LAYER_OUT_21_pos0*.bin", "llama_LAYER21_OUT_pos0*.bin"),
        ("FINAL_NORM", 99, "deep2_PROMPT_FINAL_NORM_pos0*.bin", "llama_FINAL_NORM_pos0*.bin"),
    ]

    lines = [
        "BATCH2_SPARSE_TIPS_DUAL_001",
        "authority=SPARSE_CLEAN EXPAND_V + post-SwiGLU-fix",
        "prereq=SPARSE_TIP_NUMERICAL_FLOOR_001 (L0..8 tip_eps=5e-5 FLOOR)",
        "dual: PASS if abs<=1e-6 OR (abs<=1e-4 AND rel<=1e-6); INSPECT if abs<=1e-4 AND rel<=5e-6",
        f"floor: layers<= {FLOOR_MAX_LAYER} tip_eps={FLOOR_EPS:g} → PASS_FLOOR (not dual-STOP)",
        "stop: first dual=FAIL on layer>FLOOR_MAX_LAYER (or abs>FLOOR_EPS)",
        "",
    ]
    report = {
        "tips": {},
        "first_dual_fail": None,
        "first_abs_fail": None,
        "first_layer_above_floor": None,
        "floor_eps": FLOOR_EPS,
        "floor_max_layer": FLOOR_MAX_LAYER,
    }
    first_dual = None
    first_abs = None
    first_above = None

    print("\n".join(lines[:6]))
    for name, layer, dp, lp in tips:
        df, lf = find(d2, dp), find(ll, lp)
        if not df or not lf:
            msg = f"{name:12} MISSING d={bool(df)} l={bool(lf)}"
            lines.append(msg)
            print(msg)
            if layer > FLOOR_MAX_LAYER and not first_dual:
                first_dual = name
            break
        a, b = load(df), load(lf)
        abs_g, dual, mx, mr, fb, lg = cmp(a, b)
        on_floor = layer <= FLOOR_MAX_LAYER and mx <= FLOOR_EPS
        above_floor = mx > FLOOR_EPS
        if above_floor and first_above is None and layer != 99:
            first_above = layer
            report["first_layer_above_floor"] = layer
        tip_gate = "PASS_FLOOR" if on_floor else dual
        report["tips"][name] = {
            "abs": abs_g,
            "dual": dual,
            "tip_gate": tip_gate,
            "layer": layer,
            "max_abs": mx,
            "max_rel": mr,
            "first_bad": fb,
            "largest": lg,
            "floor_class": "FLOOR" if on_floor else ("ABOVE_FLOOR" if above_floor else "AT_FLOOR"),
        }
        msg = (
            f"{name:12} abs={abs_g:7} dual={dual:7} tip_gate={tip_gate:10} "
            f"max_abs={mx:.6e} max_rel={mr:.6e} first={fb} largest={lg}"
        )
        lines.append(msg)
        print(msg)
        if abs_g == "FAIL" and not first_abs and not on_floor:
            first_abs = name
            report["first_abs_fail"] = name
        # Floor layers never dual-STOP the ladder.
        if on_floor:
            continue
        if dual == "FAIL" and not first_dual:
            first_dual = name
            report["first_dual_fail"] = name
            lines.append(f"STOP at {name} (dual FAIL above floor) — expand only this band")
            print(f"STOP at {name}")
            break

    lines.append("")
    lines.append(f"FIRST_ABS_FAIL={first_abs}")
    lines.append(f"FIRST_DUAL_FAIL={first_dual}")
    lines.append(f"FIRST_LAYER_ABOVE_FLOOR={first_above}")
    if not first_dual:
        lines.append("DISPOSITION: sparse tips dual-PASS/INSPECT through scored set")
        lines.append("NEXT: tip-align FINAL_NORM if still abs-FAIL; then LOGITS/ARGMAX")
    else:
        lines.append(
            f"DISPOSITION: expand {first_dual} under EXPAND_V; "
            "L0..8 ULP floor is CLOSED (SPARSE_TIP_NUMERICAL_FLOOR_001)"
        )

    report["first_dual_fail"] = first_dual
    (out / "LADDER.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nFIRST_ABS_FAIL={first_abs}")
    print(f"FIRST_DUAL_FAIL={first_dual}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
