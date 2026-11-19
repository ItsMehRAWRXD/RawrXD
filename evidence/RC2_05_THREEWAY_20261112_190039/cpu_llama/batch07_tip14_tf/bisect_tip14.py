#!/usr/bin/env python3
"""Bisect tip14: eng STAGE vs d2_rt TF vs llama_tf (prefix through tip13=387)."""
import glob
import os
import re
import numpy as np

EV = r"F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039\cpu_llama\batch07_tip14_tf"
S = os.path.join(EV, "stage_engine")
D = os.path.join(EV, "d2_rt")
L = os.path.join(EV, "llama_tf")
OUT = os.path.join(EV, "BISECT_TIP14.txt")
lines = []


def w(s=""):
    lines.append(s)
    print(s)


def load(p):
    return np.fromfile(p, dtype=np.float32)


def mx(a, b):
    n = min(a.size, b.size)
    if n == 0:
        return float("nan"), float("nan"), -1
    d = np.abs(a[:n].astype(np.float64) - b[:n].astype(np.float64))
    return float(d.max()), float(np.sqrt(np.mean(d * d))), int(np.argmax(d))


def latest(key, pos, stage=S):
    files = [
        f
        for f in glob.glob(os.path.join(stage, f"deep2_{key}_pos{pos}_*.bin"))
        if f.endswith(".bin")
    ]

    def seq(f):
        m = re.search(r"_seq(\d+)\.bin$", f)
        return int(m.group(1)) if m else -1

    files.sort(key=seq)
    return files[-1] if files else None


def find_tf(pos, layer, names):
    for name in names:
        cands = sorted(glob.glob(os.path.join(D, f"d2_pos{pos}_blk{layer}_*_{name}.bin")))
        if cands:
            return cands[0]
    return None


def status(m):
    if m < 1e-4:
        return "MATCH"
    if m < 1e-3:
        return "NEAR"
    return "MISMATCH"


w("BISECT tip14 TF prefix through tip13=387")
w("ENG continuous STAGE (2nd gen) vs d2_rt TF vs llama_tf")
w("")

ep = latest("LOGITS", 23) or latest("TIP_LOGITS", 23)
a = load(ep)
n = min(a.size, 151936)
raw = int(np.argmax(a[:n]))
b = a.copy()
for t in range(151643, 151657):
    if t < b.size:
        b[t] = -np.inf
masked = int(np.argmax(b[:n]))
w(
    f"ENG@23 file={os.path.basename(ep)} raw={raw} eogmask={masked} "
    f"15233={a[15233]:.6f} 29213={a[29213]:.6f}"
)
ta = load(os.path.join(D, "d2_logits_pos22.bin"))
tn = min(ta.size, n)
ti = int(np.argmax(ta[:tn]))
mxa, rms, _ = mx(a[:tn], ta[:tn])
w(
    f"D2RT@22 arg={ti} 15233={ta[15233]:.6f} 29213={ta[29213]:.6f} "
    f"vs_eng maxAbs={mxa:.6e} rms={rms:.6e}"
)
la = load(os.path.join(L, "ref_logits_pos22.bin"))
ln = min(la.size, n)
li = int(np.argmax(la[:ln]))
mxa2, rms2, _ = mx(a[:ln], la[:ln])
w(
    f"LLAMA_TF@22 arg={li} 15233={la[15233]:.6f} 29213={la[29213]:.6f} "
    f"vs_eng maxAbs={mxa2:.6e} rms={rms2:.6e}"
)
mxa3, rms3, _ = mx(ta[:ln], la[:ln])
w(f"D2RT vs LLAMA_TF maxAbs={mxa3:.6e} rms={rms3:.6e}")
w("NOTE: continuous llama-cli tip14=29213; TF/single-token llama tip14=15233")
w("")

w("=== layerwise eng@pos22 vs d2_rt@pos22 (forward of tip13=387) ===")
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
for layer in range(0, 28):
    for ekey, names in pairs:
        ep2 = latest(f"{ekey}_{layer}", 22)
        tp = find_tf(22, layer, names)
        if ep2 is None or tp is None:
            continue
        mxa, rms, arg = mx(load(ep2), load(tp))
        st = status(mxa)
        if layer < 3 or mxa >= 1e-4:
            w(f"L{layer} {ekey}: maxAbs={mxa:.6e} rms={rms:.6e} arg={arg} {st}")
        if first is None and mxa >= 1e-4:
            first = (layer, ekey, mxa, rms)
    if first and layer > first[0] + 2:
        break

w("")
if first:
    w(
        f"FIRST_DIVERGENT_OP@tip14_step L{first[0]} {first[1]} "
        f"maxAbs={first[2]:.6e} rms={first[3]:.6e}"
    )
else:
    w("FIRST_DIVERGENT_OP@tip14_step=NONE_IN_SCAN (eng≈d2_rt)")

w("")
w("=== confirm L0 pos0 ATTN still closed ===")
for ekey, names in [
    ("V", ["v"]),
    ("ATTN_PRE_O", ["attn_out"]),
    ("Q_PRE_ROPE", ["q"]),
    ("K_PRE_ROPE", ["k"]),
]:
    ep0 = latest(f"{ekey}_0", 0)
    tp0 = find_tf(0, 0, names)
    mxa, rms, _ = mx(load(ep0), load(tp0))
    w(f"pos0 L0 {ekey}: maxAbs={mxa:.6e} {status(mxa)}")

open(OUT, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("WROTE", OUT)
