#!/usr/bin/env python3
"""Bisect Deep2Engine STAGE dumps vs RuntimeGraph d2_tf / llama at teacher-forced pos."""
import glob
import os
import re
import numpy as np

EV = r"F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039"
S = os.path.join(EV, "cpu_llama", "stage_engine")
D = os.path.join(EV, "cpu_llama", "d2_tf")
L = os.path.join(EV, "cpu_llama", "llama_tf")
out = os.path.join(EV, "cpu_llama", "BISECT_ENGINE_VS_TF.txt")


def load(p):
    return np.fromfile(p, dtype=np.float32)


def latest_stage(key, pos):
    files = glob.glob(os.path.join(S, f"deep2_{key}_pos{pos}_*.bin"))
    files = [f for f in files if f.endswith(".bin")]
    if not files:
        return None

    def seq(f):
        m = re.search(r"_seq(\d+)\.bin$", f)
        return int(m.group(1)) if m else -1

    files.sort(key=seq)
    return files[-1]


def mx(a, b):
    n = min(a.size, b.size)
    if n == 0:
        return float("nan"), float("nan"), -1
    d = np.abs(a[:n].astype(np.float64) - b[:n].astype(np.float64))
    return float(d.max()), float(np.sqrt(np.mean(d * d))), int(np.argmax(d))


lines = []


def w(s):
    lines.append(s)
    print(s)


def find_tf(pos, layer, names):
    for name in names:
        cands = sorted(glob.glob(os.path.join(D, f"d2_pos{pos}_blk{layer}_*_{name}.bin")))
        if cands:
            return cands[0]
    return None


w("BISECT Deep2Engine STAGE vs RuntimeGraph d2_tf @ shared teacher-forced positions")
w("NOTE: product smoke picks 315 @ gen idx2; llama+d2_tf pick 16895")
w("")

for pos in [8, 9, 10, 11]:
    for key in [
        "LOGITS",
        "TIP_LOGITS",
        "FINAL_NORM",
        "TIP_FINAL_NORM",
        "FINAL_HIDDEN_FOR_LOGITS",
        "TIP_FINAL_HIDDEN",
    ]:
        p = latest_stage(key, pos)
        if not p:
            continue
        a = load(p)
        if "LOGITS" in key:
            n = min(a.size, 151936)
            ai = int(np.argmax(a[:n]))
            w(
                f"ENG pos={pos} {key} n={a.size} arg={ai} "
                f"315={a[315]:.6f} 16895={a[16895]:.6f} 23192={a[23192]:.6f} 576={a[576]:.6f} "
                f"file={os.path.basename(p)}"
            )
        else:
            w(
                f"ENG pos={pos} {key} n={a.size} l2={np.linalg.norm(a):.6f} "
                f"file={os.path.basename(p)}"
            )

w("")
w("=== POS10 layerwise engine vs d2_tf ===")
pairs = [
    ("ATTN_NORM", ["attn_norm"]),
    ("Q_PRE_ROPE", ["q"]),
    ("K_PRE_ROPE", ["k"]),
    ("V", ["v"]),
    ("ATTN_PRE_O", ["attn_out"]),
    ("FFN_INP", ["resid1"]),
    ("FFN_NORM", ["ffn_norm"]),
    ("FFN_GATE", ["gate"]),
    ("FFN_UP", ["up"]),
    ("FFN_ACT", ["swiglu"]),
    ("FFN_DOWN", ["ffn_out"]),
    ("POST_FFN", ["resid2"]),
]

first = None
for layer in [0, 1, 2]:
    w(f"-- layer {layer} --")
    for ekey, names in pairs:
        ep = latest_stage(f"{ekey}_{layer}", 10)
        tp = find_tf(10, layer, names)
        if ep is None or tp is None:
            w(f"  {ekey}: MISSING eng={ep is not None} tf={tp is not None}")
            continue
        ea = load(ep)
        ta = load(tp)
        mxa, rms, arg = mx(ea, ta)
        status = "MATCH" if mxa < 1e-4 else ("NEAR" if mxa < 1e-3 else "MISMATCH")
        w(
            f"  {ekey}: n={min(ea.size, ta.size)} maxAbs={mxa:.6e} rms={rms:.6e} "
            f"arg={arg} {status}"
        )
        if first is None and mxa >= 1e-3:
            first = (layer, ekey, mxa, rms)

w("")
if first:
    w(
        f"FIRST_ENGINE_VS_TF_MISMATCH layer={first[0]} op={first[1]} "
        f"maxAbs={first[2]:.6e} rms={first[3]:.6e}"
    )
else:
    w("FIRST_ENGINE_VS_TF_MISMATCH=NONE_IN_SCANNED")

w("")
w("=== hidden/final vs llama ===")
for pos in [0, 8, 9, 10]:
    lh = os.path.join(L, f"ref_hidden_pos{pos}.bin")
    if not os.path.exists(lh):
        continue
    la = load(lh)
    for key in ["FINAL_NORM", "TIP_FINAL_NORM", "FINAL_HIDDEN_FOR_LOGITS", "TIP_FINAL_HIDDEN"]:
        ep = latest_stage(key, pos)
        if not ep:
            continue
        ea = load(ep)
        mxa, rms, arg = mx(ea, la)
        w(f"pos={pos} {key} vs llama_hidden maxAbs={mxa:.6e} rms={rms:.6e} arg={arg}")
    tps = sorted(glob.glob(os.path.join(D, f"d2_pos{pos}_blk999_*_out_norm.bin")))
    if tps:
        ta = load(tps[0])
        mxa, rms, arg = mx(ta, la)
        w(f"pos={pos} d2_tf_out_norm vs llama_hidden maxAbs={mxa:.6e} rms={rms:.6e}")

w("")
w("=== logits engine vs llama ===")
for pos in [8, 9, 10]:
    lp = os.path.join(L, f"ref_logits_pos{pos}.bin")
    la = load(lp)
    for key in ["LOGITS", "TIP_LOGITS"]:
        ep = latest_stage(key, pos)
        if not ep:
            continue
        ea = load(ep)
        n = min(ea.size, la.size)
        ei = int(np.argmax(ea[:n]))
        li = int(np.argmax(la[:n]))
        mxa, rms, _ = mx(ea[:n], la[:n])
        w(
            f"pos={pos} {key}: eng_arg={ei} llama_arg={li} match={int(ei == li)} "
            f"maxAbs={mxa:.6e} e315={ea[315]:.4f} e16895={ea[16895]:.4f} "
            f"l315={la[315]:.4f} l16895={la[16895]:.4f}"
        )

open(out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("WROTE", out)
