# Gate A independent numerical parity: llama.cpp (external reference) vs Deep2.
#
# Teacher-forced, one token per position, identical token IDs and positions on
# both sides. Full logit vectors (128256 f32) dumped per position by:
#   ref : ref_dump_logits.exe  (tools/llama_dump_logits_teacher_forced.cpp,
#         built against tmp_llama_ref @ 5cdadfc326163ed1fa66cf609fb1761f7928900c)
#   d2  : deep2_parity_trace.exe (rebuilt from HEAD sources)
#
# Acceptance contract (Gate A):
#   logits cosine      >= 0.999 at every certification position
#   argmax agreement   100% across certification positions
#   first divergence   none across certified positions
#   max abs error      recorded; calibrated bound = 5% of the position's max |logit|
#                      (Q2_K on both sides vs f32 accumulation)
import json
import os
import sys

import numpy as np

E = r"F:\rawrxd\evidence\deep2_gate_a"
VOCAB = 128256
EB = VOCAB * 4
DATASETS = [("milestone", 5), ("extended", 21)]
SIDES = ["cpu", "gpu"]
COS_MIN = 0.999
REL_ABS_MAX = 0.05  # calibrated: quantization/precision-scaled bound on max-abs

out = []


def say(s=""):
    out.append(s)
    print(s)


def load(side_dir, prefix, pos):
    p = os.path.join(E, side_dir, "%s_logits_pos%d.bin" % (prefix, pos))
    if not os.path.exists(p):
        raise SystemExit("ARTIFACT FAIL: missing %s" % p)
    with open(p, "rb") as f:
        b = f.read()
    if len(b) != EB:
        raise SystemExit("ARTIFACT FAIL: %s has %d bytes, expected %d" % (p, len(b), EB))
    return np.frombuffer(b, dtype="<f4").astype(np.float64)


def compare(ds, n, side):
    rows = []
    for pos in range(n):
        ref = load("ref_head_%s" % ds, "ref", pos)
        d2 = load("d2_%s_%s" % (side, ds), "d2", pos)
        nonfinite = int(np.count_nonzero(~np.isfinite(d2)))
        diff = ref - d2
        maxabs = float(np.max(np.abs(diff)))
        rmse = float(np.sqrt(np.mean(diff * diff)))
        denom = float(np.linalg.norm(ref) * np.linalg.norm(d2))
        cos = float(np.dot(ref, d2) / denom) if denom > 0 else 0.0
        arg_r = int(np.argmax(ref))
        arg_d = int(np.argmax(d2))
        top2 = np.partition(ref, -2)
        margin = float(top2[-1] - top2[-2])
        scale = float(np.max(np.abs(ref)))
        rows.append({
            "pos": pos, "cos": cos, "maxabs": maxabs, "rmse": rmse,
            "rel_maxabs": maxabs / scale if scale > 0 else 0.0,
            "argmax_ref": arg_r, "argmax_d2": arg_d, "agree": arg_r == arg_d,
            "margin": margin, "scale": scale, "nonfinite": nonfinite,
        })
    return rows


def first_divergence(rows):
    # Divergence from the certification targets: cosine below the gate or argmax
    # disagreement or nonfinite logits. (Max-abs is a recorded, calibrated
    # measurement, not a divergence trigger.)
    for r in rows:
        if (not r["agree"]) or r["cos"] < COS_MIN or r["nonfinite"]:
            return r["pos"]
    return None


say("=== Gate A independent numerical parity (llama.cpp external reference vs Deep2) ===")
say("model: llama3.2-3b-Q2_K.gguf (sha256 EE1CA8B716933587127F6FEB9FF5A247F1E4460E72DCF6293331B9617F8A8AA2)")
say("vocab: %d logits x f32 = %d bytes per position" % (VOCAB, EB))
say("cosine gate >= %.3f | argmax 100%% | max-abs calibrated bound %.0f%% of |logit| scale" % (COS_MIN, REL_ABS_MAX * 100))
say("")

report = {"cos_min": COS_MIN, "rel_abs_max": REL_ABS_MAX, "datasets": {}}
gate_pass = True

for ds, n in DATASETS:
    say("--- dataset: %s (%d certification positions) ---" % (ds, n))
    ds_entry = {}
    for side in SIDES:
        rows = compare(ds, n, side)
        n_agree = sum(1 for r in rows if r["agree"])
        nonfinite = sum(r["nonfinite"] for r in rows)
        worst_cos = min(rows, key=lambda r: r["cos"])
        worst_abs = max(rows, key=lambda r: r["maxabs"])
        worst_rmse = max(rows, key=lambda r: r["rmse"])
        fd = first_divergence(rows)
        cos_bad = [r for r in rows if r["cos"] < COS_MIN]
        rel_bad = [r for r in rows if r["rel_maxabs"] > REL_ABS_MAX]
        # Dataset verdict per the acceptance contract: cosine >= 0.999 at every
        # position, argmax 100%, no divergence, no nonfinite. The max-abs
        # calibration is recorded separately (informational threshold).
        ok = (n_agree == n) and (nonfinite == 0) and (fd is None) and (not cos_bad)
        if not ok:
            gate_pass = False
        say("[%s/%s] argmax agreement: %d/%d" % (ds, side, n_agree, n))
        say("[%s/%s] worst cosine: %.10f (pos %d)" % (ds, side, worst_cos["cos"], worst_cos["pos"]))
        say("[%s/%s] worst max-abs: %.6f (pos %d, %.3f%% of scale %.3f)"
            % (ds, side, worst_abs["maxabs"], worst_abs["pos"], worst_abs["rel_maxabs"] * 100, worst_abs["scale"]))
        say("[%s/%s] worst rmse: %.6f (pos %d)" % (ds, side, worst_rmse["rmse"], worst_rmse["pos"]))
        say("[%s/%s] nonfinite logits: %d" % (ds, side, nonfinite))
        say("[%s/%s] first divergence: %s" % (ds, side, "none" if fd is None else "pos %d" % fd))
        say("[%s/%s] positions below cosine gate: %d" % (ds, side, len(cos_bad)))
        say("[%s/%s] positions over calibrated max-abs bound: %d (recorded, informational)" % (ds, side, len(rel_bad)))
        say("[%s/%s] verdict: %s" % (ds, side, "PASS" if ok else "FAIL"))
        for r in rows:
            say("    pos %2d: cos=%.10f maxabs=%.6f rmse=%.6f argmax ref=%d d2=%d %s"
                % (r["pos"], r["cos"], r["maxabs"], r["rmse"], r["argmax_ref"], r["argmax_d2"],
                   "" if r["agree"] else "<-- ARGMAX MISMATCH (margin=%.6f)" % r["margin"]))
        ds_entry[side] = {"rows": rows, "argmax_agree": n_agree, "positions": n,
                          "worst_cos": worst_cos["cos"], "worst_cos_pos": worst_cos["pos"],
                          "worst_maxabs": worst_abs["maxabs"], "worst_maxabs_pos": worst_abs["pos"],
                          "worst_rmse": worst_rmse["rmse"], "nonfinite": nonfinite,
                          "cos_below_gate": len(cos_bad), "rel_abs_over_bound": len(rel_bad),
                          "first_divergence": fd, "verdict": "PASS" if ok else "FAIL"}
        say("")
    report["datasets"][ds] = ds_entry

report["verdict"] = "PASS" if gate_pass else "FAIL"
say("GATE_A_VERDICT=%s" % report["verdict"])

with open(os.path.join(E, "gate_a_compare.json"), "w", encoding="utf-8") as f:
    json.dump(report, f, indent=1)
with open(os.path.join(E, "gate_a_compare.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
print("wrote gate_a_compare.txt/.json")
