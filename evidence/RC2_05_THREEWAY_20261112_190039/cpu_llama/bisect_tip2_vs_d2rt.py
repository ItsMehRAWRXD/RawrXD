#!/usr/bin/env python3
"""Post-F16 tip2: eng batch05_final (cont, tip0/1 MATCH) vs tip2 RuntimeGraph TF."""
import glob
import os
import re
import numpy as np

EV = r"F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039\cpu_llama"
S = os.path.join(EV, "batch05_final", "stage_engine")
D = os.path.join(EV, "batch05_tip2_tf", "d2_rt")
L = os.path.join(EV, "llama_tf")
OUT = os.path.join(EV, "BISECT_TIP2_POST_F16.txt")

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


def latest(key, pos):
    files = [
        f
        for f in glob.glob(os.path.join(S, f"deep2_{key}_pos{pos}_*.bin"))
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
    if not np.isfinite(m):
        return "NAN"
    if m < 1e-4:
        return "MATCH"
    if m < 1e-3:
        return "NEAR"
    return "MISMATCH"


w("BISECT tip2 POST-F16: eng batch05_final vs batch05_tip2_tf/d2_rt")
w("TF tokens=prompt+576+23192; tip2 logits @ TF pos10 / eng STAGE pos11")
w("")

# Tip2 logits
eng = latest("LOGITS", 11) or latest("TIP_LOGITS", 11)
tf = os.path.join(D, "d2_logits_pos10.bin")
ll = os.path.join(L, "ref_logits_pos10.bin")
w("=== tip2 logits ===")
if eng and os.path.exists(tf):
    ea, ta = load(eng), load(tf)
    n = min(ea.size, ta.size, 151936)
    # EOG mask eng for display
    eb = ea.copy()
    for t in range(151643, 151657):
        if t < eb.size:
            eb[t] = -np.inf
    w(
        f"ENG@11 arg_raw={int(np.argmax(ea[:n]))} arg_eogmask={int(np.argmax(eb[:n]))} "
        f"315={ea[315]:.6f} 16895={ea[16895]:.6f} 63762={ea[63762]:.6f}"
    )
    w(
        f"TF @10 arg={int(np.argmax(ta[:n]))} "
        f"315={ta[315]:.6f} 16895={ta[16895]:.6f} 63762={ta[63762]:.6f}"
    )
    mxa, rms, arg = mx(ea[:n], ta[:n])
    w(f"eng vs tip2_tf maxAbs={mxa:.6e} rms={rms:.6e} arg={arg} {status(mxa)}")
    if os.path.exists(ll):
        la = load(ll)
        ln = min(n, la.size)
        w(
            f"llama@10 arg={int(np.argmax(la[:ln]))} "
            f"315={la[315]:.6f} 16895={la[16895]:.6f}"
        )
        mxa2, rms2, _ = mx(ta[:ln], la[:ln])
        w(f"tip2_tf vs llama maxAbs={mxa2:.6e} rms={rms2:.6e} {status(mxa2)}")
        mxa3, rms3, _ = mx(ea[:ln], la[:ln])
        w(f"eng vs llama maxAbs={mxa3:.6e} rms={rms3:.6e} {status(mxa3)}")
else:
    w(f"MISSING eng={eng} tf={os.path.exists(tf)}")

w("")
w("=== layerwise eng@pos10 vs tip2_tf@pos10 (forward of 23192) ===")
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
for layer in range(28):
    printed = False
    for ekey, names in pairs:
        ep = latest(f"{ekey}_{layer}", 10)
        tp = find_tf(10, layer, names)
        if ep is None or tp is None:
            if layer < 3:
                w(f"L{layer} {ekey}: MISSING eng={ep is not None} tf={tp is not None}")
            continue
        mxa, rms, arg = mx(load(ep), load(tp))
        st = status(mxa)
        if layer < 4 or mxa >= 1e-4:
            w(f"L{layer} {ekey}: maxAbs={mxa:.6e} rms={rms:.6e} arg={arg} {st}")
            printed = True
        if first is None and mxa >= 1e-4:
            first = (layer, ekey, mxa, rms)
    if first and layer >= first[0] + 3 and not printed:
        break

w("")
if first:
    w(
        f"FIRST_CLEAR_POST_F16_TIP2 layer={first[0]} op={first[1]} "
        f"maxAbs={first[2]:.6e} rms={first[3]:.6e}"
    )
else:
    w("FIRST_CLEAR_POST_F16_TIP2=NONE")

# PRE_O identity at pos10 (attend=11, not identity)
w("")
w("=== L0 pos10 PRE_O vs tile(F16 V) (attend>1 ⇒ expect MIS if scores path) ===")
v = load(latest("V_0", 10))
pre = load(latest("ATTN_PRE_O_0", 10))
hd, nkv, nh = 128, v.size // 128, pre.size // 128
gs = nh // nkv
vf = v.astype(np.float16).astype(np.float32)
t16 = np.zeros(nh * hd, np.float32)
t32 = np.zeros(nh * hd, np.float32)
for h in range(nh):
    kv = h // gs
    t16[h * hd : (h + 1) * hd] = vf[kv * hd : (kv + 1) * hd]
    t32[h * hd : (h + 1) * hd] = v[kv * hd : (kv + 1) * hd]
w(f"PRE vs tileF32 maxAbs={mx(pre,t32)[0]:.6e}")
w(f"PRE vs tileF16 maxAbs={mx(pre,t16)[0]:.6e}")
tp = find_tf(10, 0, ["attn_out", "v"])
if tp:
    w(f"eng PRE vs tf attn_out maxAbs={mx(pre, load(find_tf(10,0,['attn_out'])))[0]:.6e}")
    w(f"eng V vs tf V maxAbs={mx(v, load(find_tf(10,0,['v'])))[0]:.6e}")

# Q/K post-rope vs pre: confirm RoPE applied
w("")
w("=== L0 pos10 Q/K PRE vs POST (RoPE delta) ===")
for side in ("Q", "K"):
    pre_p = latest(f"{side}_PRE_ROPE_0", 10)
    post_p = latest(f"{side}_POST_ROPE_0", 10)
    if pre_p and post_p:
        mxa, rms, _ = mx(load(pre_p), load(post_p))
        w(f"{side} PRE vs POST maxAbs={mxa:.6e} rms={rms:.6e}")

open(OUT, "w", encoding="utf-8").write("\n".join(lines) + "\n")
w(f"WROTE {OUT}")
