#!/usr/bin/env python3
"""ATTN_OUT_14@pos0 closability vs gpu_ref. Prior O-proj REFUTED. PROMOTE=0."""
from __future__ import annotations

import glob
import hashlib
import os
from datetime import datetime

import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gd = os.path.join(ev, "stage_dump_ffn_down_2_xdonediv_cascade")
ref = os.path.join(ev, "stage_dump_gpu_ref")
cmp14 = os.path.join(ev, "_cmp_attn_out14_stage")
ABS_ATTN = 1e-4
ABS_FFN = 1e-5
ABS_LAYER = 1e-4


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


def cmp_tol(a, b, tol):
    n = min(len(a), len(b))
    d = np.abs(a[:n] - b[:n])
    mx = float(d.max()) if n else float("nan")
    idx = int(np.argmax(d)) if n else -1
    ngt = int(np.sum(d > tol))
    return mx, idx, ngt, n, mx > tol


lines = [
    "GPU_PARITY_ATTN_OUT_14_CLOSE_001.probe",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
    "PROMOTE=0 TIP_CLIMB=HOLD DENSE_MATCH=HOLD",
    f"DUMP={gd}",
    f"REF={ref} (best-match llama_*)",
    "PRIOR_OPROJ=GPU_PARITY_ATTN_OUT_14_OPROJ_001 REFUTED",
    "PRIOR_PRE_O_11=GPU_PARITY_ATTN_PRE_O_11_POS0_CLOSE_001 NOT_CLOSABLE",
]

spv = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv"
spv_sha = sha_file(spv)
spv_len = os.path.getsize(spv)
lines.append(f"SPV_PIN={spv_sha} LEN={spv_len} HELD={int(spv_sha.startswith('40E76D2A'))}")

# --- L14@pos0 chain ---
chain = [
    ("LAYER13_OUT", ABS_LAYER, "deep2_LAYER13_OUT_pos0*.bin", "llama_LAYER13_OUT_pos0*.bin"),
    ("ATTN_NORM_14", ABS_ATTN, "deep2_ATTN_NORM_14_pos0*.bin", "llama_ATTN_NORM_14_pos0*.bin"),
    ("V_14", ABS_ATTN, "deep2_V_14_pos0*.bin", "llama_TENS_Vcur_14_pos0*n256*.bin"),
    ("ATTN_PRE_O_14", ABS_ATTN, "deep2_ATTN_PRE_O_14_pos0*.bin", "llama_ATTN_PRE_O_14_pos0*.bin"),
    ("ATTN_OUT_14", ABS_ATTN, "deep2_ATTN_OUT_14_pos0*.bin", "llama_ATTN_OUT_14_pos0*.bin"),
    ("FFN_INP_14", ABS_ATTN, "deep2_FFN_INP_14_pos0*.bin", "llama_FFN_INP_14_pos0*.bin"),
    ("FINAL_NORM", ABS_ATTN, "deep2_FINAL_NORM_pos0*.bin", "llama_REF_FINAL*.bin"),
]

results = {}
lines.append("--- L14@pos0 best-match chain ---")
for name, tol, gpat, rpat in chain:
    gp = find_all(gd, gpat)
    cands = find_all(ref, rpat)
    alt = find_all(ref, f"llama_{name}_pos0*.bin")
    for a in alt:
        if a not in cands:
            cands.append(a)
    if name == "ATTN_OUT_14":
        for a in find_all(cmp14, "llama_ATTN_OUT_14.bin"):
            if a not in cands:
                cands.append(a)
    if name == "FINAL_NORM":
        for a in find_all(cmp14, "llama_REF_FINAL*.bin"):
            if a not in cands:
                cands.append(a)
        for a in find_all(ref, "llama_REF_FINAL*.bin"):
            if a not in cands:
                cands.append(a)
    if name == "ATTN_PRE_O_14":
        for a in find_all(cmp14, "llama_ATTN_PRE_O_14.bin"):
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
    results[name] = (mx, fail, tol, rp, gp[0])
    lines.append(
        f"{name}: maxAbs={mx:.6e} @idx{idx} n_gt={ngt}/{n} tol={tol:g} "
        f"FUNCTIONAL_FAIL={fail} ref={os.path.basename(rp)}"
    )

# --- Residual add: FFN_INP ?= ATTN_OUT + LAYER13_OUT ---
lines.append("--- Residual add identity ---")
if all(k in results for k in ("ATTN_OUT_14", "LAYER13_OUT", "FFN_INP_14")):
    ao = load(results["ATTN_OUT_14"][4])
    l13 = load(results["LAYER13_OUT"][4])
    fi = load(results["FFN_INP_14"][4])
    recon = ao + l13
    mx, idx, ngt, n, fail = cmp_tol(fi, recon, ABS_ATTN)
    lines.append(
        f"deep2_FFN_INP_vs_OUT+L13: maxAbs={mx:.6e} @idx{idx} n_gt={ngt}/{n} "
        f"UNDER_TOL={int(not fail)} BITEXACT={int(mx == 0.0)}"
    )
    # delta add: d(FFN) vs d(OUT)+d(L13) using best-match refs
    ao_r = load(results["ATTN_OUT_14"][3])
    l13_r = load(results["LAYER13_OUT"][3])
    fi_r = load(results["FFN_INP_14"][3])
    n2 = min(len(ao), len(ao_r), len(l13), len(l13_r), len(fi), len(fi_r))
    d_fi = fi[:n2] - fi_r[:n2]
    d_sum = (ao[:n2] - ao_r[:n2]) + (l13[:n2] - l13_r[:n2])
    mx_d, idx_d, ngt_d, _, fail_d = cmp_tol(d_fi, d_sum, ABS_ATTN)
    lines.append(
        f"delta_FFN_vs_delta_OUT+delta_L13: maxAbs={mx_d:.6e} @idx{idx_d} "
        f"UNDER_TOL={int(not fail_d)}"
    )

# --- O-proj amplify: OUT residual vs PRE_O residual ---
lines.append("--- O-proj amplify vs PRE_O ---")
amp_ratio = float("nan")
if "ATTN_OUT_14" in results and "ATTN_PRE_O_14" in results:
    out_mx = results["ATTN_OUT_14"][0]
    pre_mx = results["ATTN_PRE_O_14"][0]
    amp_ratio = out_mx / pre_mx if pre_mx > 0 else float("nan")
    lines.append(
        f"ATTN_PRE_O_14 maxAbs={pre_mx:.6e} FUNCTIONAL_FAIL={results['ATTN_PRE_O_14'][1]}"
    )
    lines.append(
        f"ATTN_OUT_14 maxAbs={out_mx:.6e} FUNCTIONAL_FAIL={results['ATTN_OUT_14'][1]}"
    )
    lines.append(f"OUT_vs_PRE_O_amp_ratio={amp_ratio:.6e}")
    # Prior OPROJ seal: host(pre_deep2) vs deep2_OUT bitexact; kernel OK on clean L2
    lines.append("PRIOR_REFUTED=O_PROJ_WEIGHT_LOAD · LAYOUT · ACCUM · SPV_NE_HOST_Q4KxQ8K")
    lines.append("PRIOR_L2_ATTN_OUT_maxAbs≈1.19e-07 (kernel OK on clean inputs)")

# --- Counterfactual: if PRE_O matched, would OUT close? (amplify law) ---
lines.append("--- Closability law ---")
pre_fail = results.get("ATTN_PRE_O_14", (float("nan"), 1))[1]
out_fail = results.get("ATTN_OUT_14", (float("nan"), 1))[1]
l13_fail = results.get("LAYER13_OUT", (float("nan"), 1))[1]
norm_fail = results.get("ATTN_NORM_14", (float("nan"), 1))[1]
fi_fail = results.get("FFN_INP_14", (float("nan"), 1))[1]
fn = results.get("FINAL_NORM", (float("nan"), 1))

# residual add closed?
add_ok = any("deep2_FFN_INP_vs_OUT+L13:" in ln and "UNDER_TOL=1" in ln for ln in lines)
delta_ok = any("delta_FFN_vs_delta_OUT+delta_L13:" in ln and "UNDER_TOL=1" in ln for ln in lines)

closable = 0
cause = "UNKNOWN"
true_next = "ATTN_OUT_14"
if out_fail == 0:
    closable = 1
    cause = "FUNCTIONAL_CLOSE"
    true_next = "FINAL_NORM" if fn[1] else "NONE"
elif pre_fail == 1 and out_fail == 1:
    # O-proj already REFUTED; OUT is amplify of PRE_O (+ upstream L13)
    closable = 0
    cause = "O_PROJ_AMPLIFY_OF_PRE_O_14_PLUS_LAYER13_CASCADE__OPROJ_REFUTED"
    true_next = "FINAL_NORM"
elif pre_fail == 0 and out_fail == 1:
    # PRE_O clean but OUT fails → native O-proj closable (contradicts prior REFUTED on dirty dump)
    closable = 1
    cause = "O_PROJ_NATIVE_CLOSABLE_PRE_O_CLEAN"
    true_next = "ATTN_OUT_14"
elif not add_ok:
    closable = 1
    cause = "RESIDUAL_ADD_BUG_CLOSABLE"
else:
    closable = 0
    cause = "ATTN_OUT_14_FAIL_UNATTRIBUTED"
    true_next = "FINAL_NORM"

out_mx = results.get("ATTN_OUT_14", (float("nan"), 1))[0]
pre_mx = results.get("ATTN_PRE_O_14", (float("nan"), 1))[0]
fn_mx = fn[0]
fn_fail = fn[1]

lines += [
    "--- DISPOSITION ---",
    f"ATTN_OUT_14 maxAbs={out_mx:.6e} FUNCTIONAL_FAIL={out_fail}",
    f"ATTN_PRE_O_14 maxAbs={pre_mx:.6e} FUNCTIONAL_FAIL={pre_fail}",
    f"LAYER13_OUT maxAbs={results.get('LAYER13_OUT', (float('nan'), 1))[0]:.6e} FUNCTIONAL_FAIL={l13_fail}",
    f"ATTN_NORM_14 maxAbs={results.get('ATTN_NORM_14', (float('nan'), 1))[0]:.6e} FUNCTIONAL_FAIL={norm_fail}",
    f"FFN_INP_14 maxAbs={results.get('FFN_INP_14', (float('nan'), 1))[0]:.6e} FUNCTIONAL_FAIL={fi_fail}",
    f"FINAL_NORM maxAbs={fn_mx:.6e} FUNCTIONAL_FAIL={fn_fail}",
    f"RESIDUAL_ADD_UNDER_TOL={int(add_ok)} DELTA_ADD_UNDER_TOL={int(delta_ok)}",
    f"OUT_vs_PRE_O_amp_ratio={amp_ratio:.6e}",
    f"ATTN_OUT_14_CLOSABLE={closable}",
    f"ROOT={cause}",
    f"TRUE_NEXT={true_next}",
    "SPV_40E76D2A=HELD TIP_6754616E=HOLD PCT=67/48/48 MF_qdim099=HOLD",
    "DENSE_MATCH=HOLD PROMOTE=0 TIP_CLIMB=HOLD",
    "END",
]

outp = os.path.join(ev, "GPU_PARITY_ATTN_OUT_14_CLOSE_001.probe.txt")
with open(outp, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print("\n".join(lines))
print("WROTE", outp)
