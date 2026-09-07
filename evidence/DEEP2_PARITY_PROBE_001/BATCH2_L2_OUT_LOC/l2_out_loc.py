#!/usr/bin/env python3
"""BATCH2_L2_OUT_LOC — freeze L2_OUT baseline; operand ladder; scalar SiLU."""
from __future__ import annotations

import json
import math
import struct
from pathlib import Path

PASS, INSPECT, FAIL = 1e-6, 1e-5, None
EPS = 1e-6


def load(path: Path):
    b = path.read_bytes()
    n = len(b) // 4
    return list(struct.unpack(f"<{n}f", b)), b


def cmp(a, b, eps=EPS):
    assert len(a) == len(b), (len(a), len(b))
    max_abs = 0.0
    largest = -1
    first = -1
    exact = 0
    for i, (x, y) in enumerate(zip(a, b)):
        d = abs(x - y)
        if d == 0:
            exact += 1
        if d > max_abs:
            max_abs = d
            largest = i
        if first < 0 and d > eps:
            first = i
    if max_abs <= PASS:
        gate = "PASS"
    elif max_abs <= INSPECT:
        gate = "INSPECT"
    else:
        gate = "FAIL"
    return {
        "gate": gate,
        "max_abs": max_abs,
        "first_bad": first,
        "largest": largest,
        "exact": exact,
        "n": len(a),
        "a_at_first": a[first] if first >= 0 else None,
        "b_at_first": b[first] if first >= 0 else None,
        "a_at_largest": a[largest] if largest >= 0 else None,
        "b_at_largest": b[largest] if largest >= 0 else None,
    }


def silu(x: float) -> float:
    if x > 20.0:
        return x
    if x < -20.0:
        return 0.0
    return x / (1.0 + math.exp(-x))


def find_one(dir: Path, pat: str) -> Path:
    xs = sorted(dir.glob(pat))
    if not xs:
        raise FileNotFoundError(f"{dir}/{pat}")
    return xs[0]


def main():
    root = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001")
    l2 = root / "BATCH2_L2_CLEAN_001"
    sc = root / "BATCH2_SPARSE_CLEAN_001"
    d2 = l2 / "deep2_swiglu_fix"
    if not d2.exists():
        d2 = sc / "deep2_post_swiglu_fix"
    ll = l2 / "llama"
    # LAYER2_OUT llama tip dump lives under SPARSE_CLEAN (EXPAND_V sparse CB)
    ll_tip = sc / "llama"

    out_dir = root / "BATCH2_L2_OUT_LOC"
    out_dir.mkdir(parents=True, exist_ok=True)

    stages = [
        ("ATTN_NORM_2", "deep2_ATTN_NORM_2_pos0*.bin", "llama_ATTN_NORM_2_pos0*.bin", d2, ll),
        ("ATTN_OUT_2", "deep2_ATTN_OUT_2_pos0*.bin", "llama_ATTN_OUT_2_pos0*.bin", d2, ll),
        ("FFN_INP_2", "deep2_FFN_INP_2_pos0*.bin", "llama_FFN_INP_2_pos0*.bin", d2, ll),
        ("FFN_NORM_2", "deep2_FFN_NORM_2_pos0*.bin", "llama_FFN_NORM_2_pos0*.bin", d2, ll),
        ("FFN_GATE_2", "deep2_FFN_GATE_2_pos0*.bin", "llama_FFN_GATE_2_pos0*.bin", d2, ll),
        ("FFN_UP_2", "deep2_FFN_UP_2_pos0*.bin", "llama_FFN_UP_2_pos0*.bin", d2, ll),
        ("FFN_ACT_2", "deep2_FFN_ACT_2_pos0*.bin", "llama_FFN_ACT_2_pos0*.bin", d2, ll),
        ("FFN_DOWN_2", "deep2_FFN_DOWN_2_pos0*.bin", "llama_FFN_DOWN_2_pos0*.bin", d2, ll),
        ("POST_FFN_2", "deep2_POST_FFN_2_pos0*.bin", "llama_FFN_DOWN_2_pos0*.bin", d2, ll),  # llama may lack POST; compare DOWN later
        ("L2_OUT", "deep2_LAYER_OUT_2_pos0*.bin", "llama_LAYER2_OUT_pos0*.bin", d2, ll_tip),
    ]

    lines = []
    report = {
        "batch": "BATCH2_L2_OUT_LOC",
        "authority": "CLEAN EXPAND_V + post-SwiGLU-fix Deep2",
        "baseline_claim": "L2_OUT ~4.58e-5",
        "stages": {},
    }

    def log(s=""):
        print(s)
        lines.append(s)

    log("BATCH2_L2_OUT_LOC")
    log(f"deep2={d2}")
    log(f"llama_ffn={ll}")
    log(f"llama_tip={ll_tip}")
    log(f"eps_pass={PASS} eps_inspect={INSPECT}")
    log("")
    log("=== stage ladder (Deep2 vs llama) ===")

    first_fail = None
    for name, dp, lp, dd, ld in stages:
        try:
            df = find_one(dd, dp)
            lf = find_one(ld, lp)
        except FileNotFoundError as e:
            log(f"{name:12} MISSING {e}")
            continue
        if name == "POST_FFN_2":
            # Prefer llama POST if present; else skip this alias
            alt = list(ld.glob("llama_POST_FFN_2_pos0*.bin")) or list(ld.glob("llama_LAYER2_OUT_pos0*.bin"))
            # Residual identity checked separately
            pass
        a, _ = load(df)
        b, _ = load(lf)
        if len(a) != len(b):
            log(f"{name:12} LEN_MISMATCH {len(a)} vs {len(b)}")
            continue
        r = cmp(a, b)
        report["stages"][name] = {**r, "deep2": df.name, "llama": lf.name}
        log(
            f"{name:12} {r['gate']:7} max_abs={r['max_abs']:.6e} "
            f"first_bad={r['first_bad']} largest={r['largest']} "
            f"exact={r['exact']}/{r['n']}"
        )
        if r["first_bad"] is not None and r["first_bad"] >= 0:
            log(
                f"             @first_bad d={r['a_at_first']:.8e} l={r['b_at_first']:.8e} "
                f"delta={r['a_at_first']-r['b_at_first']:.8e}"
            )
        if r["gate"] == "FAIL" and first_fail is None:
            first_fail = name

    # Residual identities on Deep2
    log("")
    log("=== Deep2 residual identities (oracle-independent) ===")
    try:
        # Need LAYER1_OUT for FFN_INP = L1 + ATTN_OUT
        l1 = find_one(d2, "deep2_LAYER_OUT_1_pos0*.bin") if list(d2.glob("deep2_LAYER_OUT_1_pos0*.bin")) else None
        if l1 is None:
            # try parent deep2 dirs
            for cand in [l2 / "deep2", sc / "deep2_post_swiglu_fix", sc / "deep2"]:
                xs = list(cand.glob("deep2_LAYER_OUT_1_pos0*.bin"))
                if xs:
                    l1 = xs[0]
                    break
        attn = find_one(d2, "deep2_ATTN_OUT_2_pos0*.bin")
        ffn_inp = find_one(d2, "deep2_FFN_INP_2_pos0*.bin")
        down = find_one(d2, "deep2_FFN_DOWN_2_pos0*.bin")
        post = find_one(d2, "deep2_POST_FFN_2_pos0*.bin")
        lout = find_one(d2, "deep2_LAYER_OUT_2_pos0*.bin")

        A, _ = load(attn)
        Fi, _ = load(ffn_inp)
        D, _ = load(down)
        P, _ = load(post)
        Lo, _ = load(lout)

        r_post = cmp(P, Lo)
        log(f"POST_FFN_2 == LAYER_OUT_2     {r_post['gate']:7} max_abs={r_post['max_abs']:.6e}")

        if l1 is not None:
            L1, _ = load(l1)
            recon = [L1[i] + A[i] for i in range(len(A))]
            r_inp = cmp(Fi, recon)
            log(f"FFN_INP_2 == L1_OUT+ATTN_OUT {r_inp['gate']:7} max_abs={r_inp['max_abs']:.6e}")
            report["deep2_FFN_INP_identity"] = r_inp
        else:
            log("FFN_INP_2 == L1+ATTN         SKIP (no LAYER_OUT_1 dump)")

        recon2 = [Fi[i] + D[i] for i in range(len(D))]
        r_layer = cmp(Lo, recon2)
        log(f"L2_OUT == FFN_INP+FFN_DOWN   {r_layer['gate']:7} max_abs={r_layer['max_abs']:.6e}")
        report["deep2_L2_OUT_identity"] = r_layer
    except Exception as e:
        log(f"identity check error: {e}")

    # Scalar SiLU self-check + vs llama ACT
    log("")
    log("=== scalar SiLU (Deep2 GATE/UP) ===")
    g_path = find_one(d2, "deep2_FFN_GATE_2_pos0*.bin")
    u_path = find_one(d2, "deep2_FFN_UP_2_pos0*.bin")
    a_path = find_one(d2, "deep2_FFN_ACT_2_pos0*.bin")
    lg_path = find_one(ll, "llama_FFN_GATE_2_pos0*.bin")
    lu_path = find_one(ll, "llama_FFN_UP_2_pos0*.bin")
    la_path = find_one(ll, "llama_FFN_ACT_2_pos0*.bin")

    G, _ = load(g_path)
    U, _ = load(u_path)
    Act, _ = load(a_path)
    Gl, _ = load(lg_path)
    Ul, _ = load(lu_path)
    Actl, _ = load(la_path)

    ref_d = [silu(G[i]) * U[i] for i in range(len(G))]
    ref_l = [silu(Gl[i]) * Ul[i] for i in range(len(Gl))]

    r_self = cmp(Act, ref_d)
    r_llama_self = cmp(Actl, ref_l)
    r_act = cmp(Act, Actl)
    r_ref_vs_llama = cmp(ref_d, Actl)
    r_ref_vs_ref = cmp(ref_d, ref_l)

    log(f"Deep2 ACT == silu(G)*U         {r_self['gate']:7} max_abs={r_self['max_abs']:.6e} first_bad={r_self['first_bad']} largest={r_self['largest']}")
    log(f"llama ACT == silu(Gl)*Ul       {r_llama_self['gate']:7} max_abs={r_llama_self['max_abs']:.6e}")
    log(f"Deep2 ACT vs llama ACT         {r_act['gate']:7} max_abs={r_act['max_abs']:.6e} first_bad={r_act['first_bad']} largest={r_act['largest']}")
    log(f"silu(Gd)*Ud vs llama ACT       {r_ref_vs_llama['gate']:7} max_abs={r_ref_vs_llama['max_abs']:.6e} first_bad={r_ref_vs_llama['first_bad']}")
    log(f"silu(Gd)*Ud vs silu(Gl)*Ul     {r_ref_vs_ref['gate']:7} max_abs={r_ref_vs_ref['max_abs']:.6e} first_bad={r_ref_vs_ref['first_bad']}")

    if r_act["largest"] >= 0:
        i = r_act["largest"]
        log(
            f"  worst ACT idx={i}: Gd={G[i]:.8e} Ud={U[i]:.8e} Ad={Act[i]:.8e} "
            f"Gl={Gl[i]:.8e} Ul={Ul[i]:.8e} Al={Actl[i]:.8e} "
            f"ref_d={ref_d[i]:.8e} ref_l={ref_l[i]:.8e}"
        )
        log(
            f"  deltas: G={G[i]-Gl[i]:.8e} U={U[i]-Ul[i]:.8e} "
            f"ACT={Act[i]-Actl[i]:.8e} ref={ref_d[i]-ref_l[i]:.8e}"
        )

    report["scalar_silu"] = {
        "deep2_act_vs_ref": r_self,
        "llama_act_vs_ref": r_llama_self,
        "deep2_vs_llama_act": r_act,
        "deep2_ref_vs_llama_act": r_ref_vs_llama,
        "deep2_ref_vs_llama_ref": r_ref_vs_ref,
    }

    # Decision tree
    log("")
    log("=== DECISION ===")
    if r_self["max_abs"] > 1e-6:
        decision = "DEEP2_SILU_STILL_WRONG"
        next_todo = "fix Deep2Engine::SwiGLU further; ACT != silu(G)*U"
    elif r_ref_vs_llama["max_abs"] <= PASS and r_act["max_abs"] > PASS:
        decision = "ACT_DUMP_MISMATCH_BUT_REF_MATCHES"  # unlikely
        next_todo = "check ACT dump timing"
    elif r_ref_vs_ref["gate"] != "PASS" and r_ref_vs_llama["max_abs"] >= r_act["max_abs"] * 0.5:
        # scalar from Deep2 operands still differs from llama → upstream G/U
        decision = "SCALAR_PRESERVES_DELTA → upstream GATE/UP (or earlier)"
        next_todo = "walk back: FFN_UP/GATE → NORM → INP → ATTN_OUT (first FAIL operand)"
    elif r_self["gate"] == "PASS" and r_act["gate"] != "PASS" and r_ref_vs_llama["gate"] != "PASS":
        decision = "SCALAR_PRESERVES_DELTA → upstream operands (G/U differ)"
        next_todo = "first FAIL among GATE/UP/NORM/INP/ATTN"
    elif r_self["gate"] == "PASS" and r_act["gate"] != "PASS" and r_ref_vs_llama["gate"] == "PASS":
        decision = "SCALAR MATCHES llama ACT using Deep2 G/U — unexpected path"
        next_todo = "re-check dumps"
    else:
        # ACT close; DOWN/L2_OUT diverge → kernel
        if report["stages"].get("FFN_ACT_2", {}).get("gate") in ("PASS", "INSPECT") and report["stages"].get(
            "FFN_DOWN_2", {}
        ).get("gate") == "FAIL":
            decision = "SCALAR/ACT OK-ish → FFN_DOWN kernel / accumulation"
            next_todo = "same-operand Gate A: force llama ACT←Deep2 ACT, compare DOWN"
        else:
            decision = "SEE_FIRST_FAIL_STAGE"
            next_todo = f"expand first_fail={first_fail}"

    # Refine using first fail stage
    for s in [
        "ATTN_NORM_2",
        "ATTN_OUT_2",
        "FFN_INP_2",
        "FFN_NORM_2",
        "FFN_GATE_2",
        "FFN_UP_2",
        "FFN_ACT_2",
        "FFN_DOWN_2",
        "L2_OUT",
    ]:
        st = report["stages"].get(s)
        if st and st["gate"] == "FAIL":
            first_fail = s
            break

    log(f"FIRST_TENSOR_FAIL={first_fail}")
    log(f"CLASS={decision}")
    log(f"NEXT={next_todo}")
    report["first_tensor_fail"] = first_fail
    report["class"] = decision
    report["next"] = next_todo

    # Element-level: if ACT fails, dump top-5 worst indices
    if r_act["gate"] != "PASS":
        diffs = sorted(
            ((abs(Act[i] - Actl[i]), i) for i in range(len(Act))),
            reverse=True,
        )[:8]
        log("")
        log("=== top ACT abs deltas ===")
        for d, i in diffs:
            log(
                f"  idx={i:5d} dACT={d:.6e} Gd={G[i]:.6e} Gl={Gl[i]:.6e} "
                f"dG={G[i]-Gl[i]:.6e} Ud={U[i]:.6e} Ul={Ul[i]:.6e} dU={U[i]-Ul[i]:.6e}"
            )

    (out_dir / "LADDER.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"\nwrote {out_dir/'LADDER.txt'}")


if __name__ == "__main__":
    main()
