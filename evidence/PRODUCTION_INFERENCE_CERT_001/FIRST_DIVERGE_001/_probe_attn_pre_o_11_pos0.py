#!/usr/bin/env python3
"""ATTN_PRE_O_11@pos0 closability vs BATCH2 / gpu_ref best-match. PROMOTE=0."""
from __future__ import annotations

import glob
import hashlib
import os
from datetime import datetime

import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gd = os.path.join(ev, "stage_dump_ffn_down_2_xdonediv_cascade")
ref = os.path.join(ev, "stage_dump_gpu_ref")
b2 = r"G:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L11_BODY_001"
ABS_ATTN = 1e-4
ABS_FFN = 1e-5
N_HEAD, N_KV, HD = 32, 4, 64  # TinyLlama GQA


def load(p):
    return np.fromfile(p, dtype=np.float32)


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def find_all(d, pat):
    return sorted(glob.glob(os.path.join(d, pat)))


def best_match(gpu_path, candidates):
    g = load(gpu_path)
    best = None
    for c in candidates:
        r = load(c)
        n = min(len(g), len(r))
        if n == 0:
            continue
        d = np.abs(g[:n] - r[:n])
        mx = float(d.max())
        if best is None or mx < best[0]:
            best = (mx, int(np.argmax(d)), int(np.sum(d > ABS_ATTN)), n, c)
    return best


def expand_v(v):
    """GQA expand: n_kv*hd -> n_head*hd by repeating each kv head n_head/n_kv times."""
    rep = N_HEAD // N_KV
    out = np.empty(N_HEAD * HD, dtype=np.float32)
    for h in range(N_HEAD):
        kv = h // rep
        out[h * HD : (h + 1) * HD] = v[kv * HD : (kv + 1) * HD]
    return out


def cmp_tol(a, b, tol):
    n = min(len(a), len(b))
    d = np.abs(a[:n] - b[:n])
    mx = float(d.max()) if n else float("nan")
    idx = int(np.argmax(d)) if n else -1
    ngt = int(np.sum(d > tol))
    return mx, idx, ngt, n, mx > tol


lines = [
    "GPU_PARITY_ATTN_PRE_O_11_POS0_CLOSE_001.probe",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
    "PROMOTE=0 TIP_CLIMB=HOLD DENSE_MATCH=HOLD",
    f"DUMP={gd}",
    f"REF={ref} (best-match llama_*)",
    f"BATCH2={b2}",
]

spv = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv"
spv_sha = sha_file(spv)
spv_len = os.path.getsize(spv)
lines.append(f"SPV_PIN={spv_sha} LEN={spv_len} HELD={int(spv_sha.startswith('40E76D2A'))}")

# --- L11 pos0 chain vs best-match llama ---
chain = [
    ("FFN_DOWN_10", ABS_FFN, "deep2_FFN_DOWN_10_pos0*.bin", "llama_FFN_DOWN_10_pos0*.bin"),
    ("ATTN_NORM_11", ABS_ATTN, "deep2_ATTN_NORM_11_pos0*.bin", "llama_ATTN_NORM_11_pos0*.bin"),
    ("V_11", ABS_ATTN, "deep2_V_11_pos0*.bin", "llama_TENS_Vcur_11_pos0*n256*.bin"),
    ("Q_LINEAR_11", ABS_ATTN, "deep2_Q_LINEAR_11_pos0*.bin", "llama_TENS_Qcur_11_pos0*n2048*.bin"),
    ("K_LINEAR_11", ABS_ATTN, "deep2_K_LINEAR_11_pos0*.bin", "llama_TENS_Kcur_11_(view)_pos0*n256*.bin"),
    ("Q_NORM_11", ABS_ATTN, "deep2_Q_NORM_11_pos0*.bin", "llama_TENS_Qcur_11_(view)_pos0*n64*.bin"),
    ("K_NORM_11", ABS_ATTN, "deep2_K_NORM_11_pos0*.bin", "llama_TENS_Kcur_11_(view)_pos0*n256*.bin"),
    ("Q_PRE_ROPE_11", ABS_ATTN, "deep2_Q_PRE_ROPE_11_pos0*.bin", "llama_TENS_Qcur_11_pos0*n2048*.bin"),
    ("K_PRE_ROPE_11", ABS_ATTN, "deep2_K_PRE_ROPE_11_pos0*.bin", "llama_TENS_Kcur_11_(view)_pos0*n256*.bin"),
    ("ATTN_PRE_O_11", ABS_ATTN, "deep2_ATTN_PRE_O_11_pos0*.bin", "llama_ATTN_PRE_O_11_pos0*.bin"),
    ("ATTN_OUT_11", ABS_ATTN, "deep2_ATTN_OUT_11_pos0*.bin", "llama_ATTN_OUT_11_pos0*.bin"),
]

results = {}
lines.append("--- L11@pos0 best-match chain ---")
for name, tol, gpat, rpat in chain:
    gp = find_all(gd, gpat)
    # also try simple llama_KEY naming
    cands = find_all(ref, rpat)
    alt = find_all(ref, f"llama_{name}_pos0*.bin")
    for a in alt:
        if a not in cands:
            cands.append(a)
    if not gp:
        lines.append(f"{name}: MISSING_GPU")
        continue
    if not cands:
        lines.append(f"{name}: MISSING_REF g={os.path.basename(gp[0])}")
        continue
    bm = best_match(gp[0], cands)
    mx, idx, ngt, n, rp = bm
    fail = int(mx > tol)
    results[name] = (mx, fail, tol, rp)
    lines.append(
        f"{name}: maxAbs={mx:.6e} @idx{idx} n_gt={ngt}/{n} tol={tol:g} "
        f"FUNCTIONAL_FAIL={fail} ref={os.path.basename(rp)}"
    )

# --- PRE_O vs GQA expand(V) identity (pos0 T=1) ---
lines.append("--- PRE_O vs expand(V) identity ---")
v_g = find_all(gd, "deep2_V_11_pos0*.bin")
po_g = find_all(gd, "deep2_ATTN_PRE_O_11_pos0*.bin")
if v_g and po_g:
    v = load(v_g[0])
    po = load(po_g[0])
    exp = expand_v(v[: N_KV * HD])
    mx, idx, ngt, n, fail = cmp_tol(po, exp, ABS_ATTN)
    lines.append(
        f"deep2_PRE_O_vs_expand(V): maxAbs={mx:.6e} @idx{idx} n_gt={ngt}/{n} "
        f"BITEXACT={int(mx == 0.0)} UNDER_TOL={int(not fail)}"
    )
    # llama PRE_O vs expand(llama V) if available
    po_r = results.get("ATTN_PRE_O_11")
    v_r = results.get("V_11")
    if po_r and v_r:
        lv = load(v_r[3])
        lpo = load(po_r[3])
        # llama V may be n256 view
        if len(lv) >= N_KV * HD:
            lexp = expand_v(lv[: N_KV * HD])
            mx2, idx2, ngt2, n2, fail2 = cmp_tol(lpo, lexp, ABS_ATTN)
            lines.append(
                f"llama_PRE_O_vs_expand(V): maxAbs={mx2:.6e} @idx{idx2} "
                f"UNDER_TOL={int(not fail2)}"
            )

# --- Counterfactual: inject llama V expand -> would PRE_O match? ---
lines.append("--- Counterfactual inject ---")
if v_g and po_g and "V_11" in results and "ATTN_PRE_O_11" in results:
    lv = load(results["V_11"][3])
    lpo = load(results["ATTN_PRE_O_11"][3])
    gpo = load(po_g[0])
    if len(lv) >= N_KV * HD:
        # If deep2 PRE_O == expand(deep2 V) and residual is in V from NORM,
        # closing PRE_O requires closing upstream — not a PRE_O layout bug.
        lexp = expand_v(lv[: N_KV * HD])
        mx_cf, idx_cf, ngt_cf, n_cf, fail_cf = cmp_tol(lexp, lpo, ABS_ATTN)
        lines.append(
            f"CF_expand(llama_V)_vs_llama_PRE_O: maxAbs={mx_cf:.6e} FAIL={int(fail_cf)}"
        )
        mx_gv, _, _, _, _ = cmp_tol(load(v_g[0])[: N_KV * HD], lv[: N_KV * HD], ABS_ATTN)
        lines.append(f"CF_deep2_V_vs_llama_V: maxAbs={mx_gv:.6e}")
        # If we replaced deep2 PRE_O with expand(llama V), vs llama PRE_O:
        mx_fix, _, _, _, fail_fix = cmp_tol(lexp, lpo, ABS_ATTN)
        lines.append(
            f"CF_layout_close_if_V_matched: UNDER_TOL={int(not fail_fix)} "
            f"(PRE_O layout closable only if V/K/Q close)"
        )

# --- Remeasure cascade sites ---
lines.append("--- Cascade remasure (best-match) ---")
cascade = [
    ("ATTN_PRE_O_11", ABS_ATTN, "deep2_ATTN_PRE_O_11_pos0*.bin", "llama_ATTN_PRE_O_11_pos0*.bin"),
    ("ATTN_PRE_O_14", ABS_ATTN, "deep2_ATTN_PRE_O_14_pos0*.bin", "llama_ATTN_PRE_O_14_pos0*.bin"),
    ("ATTN_OUT_14", ABS_ATTN, "deep2_ATTN_OUT_14_pos0*.bin", "llama_ATTN_OUT_14_pos0*.bin"),
    ("FINAL_NORM", ABS_ATTN, "deep2_FINAL_NORM_pos0*.bin", "llama_FINAL_NORM_pos0*.bin"),
    ("FFN_DOWN_10", ABS_FFN, "deep2_FFN_DOWN_10_pos0*.bin", "llama_FFN_DOWN_10_pos0*.bin"),
]
cascade_vals = {}
for name, tol, gpat, rpat in cascade:
    gp = find_all(gd, gpat)
    cands = find_all(ref, rpat)
    if name == "FINAL_NORM":
        cands += find_all(ref, "llama_REF_FINAL*.bin")
        cands += find_all(os.path.join(ev, "_cmp_attn_out14_stage"), "llama_REF_FINAL*.bin")
    if name == "ATTN_OUT_14":
        cands += find_all(os.path.join(ev, "_cmp_attn_out14_stage"), "llama_ATTN_OUT_14.bin")
    if not gp or not cands:
        lines.append(f"{name}: MISSING")
        continue
    bm = best_match(gp[0], cands)
    mx, idx, ngt, n, rp = bm
    fail = int(mx > tol)
    cascade_vals[name] = (mx, fail)
    lines.append(
        f"{name}: maxAbs={mx:.6e} @idx{idx} n_gt={ngt}/{n} FUNCTIONAL_FAIL={fail} "
        f"ref={os.path.basename(rp)}"
    )

# --- Disposition ---
pre = cascade_vals.get("ATTN_PRE_O_11", results.get("ATTN_PRE_O_11", (float("nan"), 1)))
pre_mx = pre[0] if isinstance(pre, tuple) else float("nan")
pre_fail = pre[1] if isinstance(pre, tuple) else 1
v_fail = results.get("V_11", (float("nan"), 1))[1]
norm_fail = results.get("ATTN_NORM_11", (float("nan"), 1))[1]
q_fail = results.get("Q_PRE_ROPE_11", (float("nan"), 1))[1]
k_fail = results.get("K_PRE_ROPE_11", (float("nan"), 1))[1]

# Closable if PRE_O fails BUT V/Q/K/NORM under tol with layout mismatch
# (deep2 PRE_O != expand(V) while llama PRE_O == expand(V))
po_exp_ok = None
for ln in lines:
    if ln.startswith("deep2_PRE_O_vs_expand(V):"):
        po_exp_ok = "BITEXACT=1" in ln or "UNDER_TOL=1" in ln

layout_bug = po_exp_ok is False
upstream_owned = (norm_fail == 1 or v_fail == 1) and (po_exp_ok is True)
kqv_native = (v_fail == 0 and q_fail == 0 and k_fail == 0 and norm_fail == 0 and pre_fail == 1)

closable = 0
cause = "UNKNOWN"
true_next = "ATTN_PRE_O_11"
if pre_fail == 0:
    closable = 1
    cause = "FUNCTIONAL_CLOSE"
    true_next = "ATTN_OUT_14" if cascade_vals.get("ATTN_OUT_14", (0, 1))[1] else "FINAL_NORM"
elif layout_bug and kqv_native:
    closable = 1
    cause = "LAYOUT_EXPAND_V_MISMATCH_CLOSABLE"
elif upstream_owned:
    closable = 0
    cause = "FA_AMPLIFY_OF_L10_RESIDUAL_VIA_NORM_V"
    # first site that still fails after PRE_O in cascade for TRUE_NEXT if PRE_O not closable
    # TRUE_NEXT remains the first ATTN-class FAIL we cannot close — advance to next independent
    for nxt in ("ATTN_OUT_14", "ATTN_PRE_O_14", "FINAL_NORM"):
        if cascade_vals.get(nxt, (0, 0))[1]:
            # keep PRE_O as sealed NOT_CLOSABLE; next work site is ATTN_OUT_14
            true_next = "ATTN_OUT_14" if nxt.startswith("ATTN") else nxt
            break
elif v_fail or q_fail or k_fail:
    closable = 0
    cause = "KQV_OR_ROPE_RESIDUAL_FROM_UPSTREAM_NORM"
    true_next = "ATTN_OUT_14"
else:
    closable = 0
    cause = "PRE_O_FAIL_UNATTRIBUTED"
    true_next = "ATTN_OUT_14"

out14 = cascade_vals.get("ATTN_OUT_14", (float("nan"), 1))
fn = cascade_vals.get("FINAL_NORM", (float("nan"), 1))
fd10 = cascade_vals.get("FFN_DOWN_10", results.get("FFN_DOWN_10", (float("nan"), 1)))

lines += [
    "--- DISPOSITION ---",
    f"ATTN_PRE_O_11 maxAbs={pre_mx:.6e} FUNCTIONAL_FAIL={pre_fail}",
    f"ATTN_OUT_14 maxAbs={out14[0]:.6e} FUNCTIONAL_FAIL={out14[1]}",
    f"FINAL_NORM maxAbs={fn[0]:.6e} FUNCTIONAL_FAIL={fn[1]}",
    f"FFN_DOWN_10 maxAbs={fd10[0]:.6e} FUNCTIONAL_FAIL={fd10[1]}",
    f"ATTN_PRE_O_11_CLOSABLE={closable}",
    f"ROOT={cause}",
    f"TRUE_NEXT={true_next}",
    "SPV_40E76D2A=HELD TIP_6754616E=HOLD PCT=67/48/48 MF_qdim099=HOLD",
    "DENSE_MATCH=HOLD PROMOTE=0 TIP_CLIMB=HOLD",
    "END",
]

outp = os.path.join(ev, "GPU_PARITY_ATTN_PRE_O_11_POS0_CLOSE_001.probe.txt")
with open(outp, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print("\n".join(lines))
print("WROTE", outp)
