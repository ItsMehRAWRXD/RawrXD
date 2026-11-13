#!/usr/bin/env python3
"""Post-F16: bisect eng vs d2_tf/llama at tip2 (prefix prompt+576+23192)."""
import glob
import os
import re
import numpy as np

EV = r"F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039\cpu_llama"
S = os.path.join(EV, "batch05_final", "stage_engine")
D = os.path.join(EV, "d2_tf")
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


w("BISECT tip2 post-F16 — eng batch05_final vs d2_tf/llama")
w("Prefix tip0/1 MATCH (576,23192) ⇒ eng@pos10/11 comparable to TF")
w("")

# Tip logits: pos9=gen0, pos10=gen1, pos11=gen2(idx2)
w("=== tip logits (EOG-masked argmax) ===")
for pos in [9, 10, 11]:
    ep = latest("LOGITS", pos) or latest("TIP_LOGITS", pos)
    if not ep:
        w(f"pos{pos}: MISSING")
        continue
    a = load(ep)
    n = min(a.size, 151936)
    raw = int(np.argmax(a[:n]))
    b = a.copy()
    for t in range(151643, 151657):
        if t < b.size:
            b[t] = -np.inf
    masked = int(np.argmax(b[:n]))
    w(
        f"ENG pos{pos}: raw={raw} eogmask={masked} "
        f"315={a[315]:.6f} 16895={a[16895]:.6f} 63762={a[63762]:.6f} "
        f"576={a[576]:.6f} 23192={a[23192]:.6f} file={os.path.basename(ep)}"
    )
    # llama: STAGE pos9≈llama pos8 tip0; pos10≈llama pos9; pos11≈llama pos10
    lp = os.path.join(L, f"ref_logits_pos{pos - 1}.bin")
    if os.path.exists(lp):
        la = load(lp)
        ln = min(la.size, n)
        li = int(np.argmax(la[:ln]))
        mxa, rms, _ = mx(a[:ln], la[:ln])
        w(
            f"  vs llama_ref_logits_pos{pos-1}: llama_arg={li} maxAbs={mxa:.6e} rms={rms:.6e} "
            f"l315={la[315]:.6f} l16895={la[16895]:.6f}"
        )
    tps = sorted(
        glob.glob(os.path.join(D, f"d2_logits_pos{pos-1}.bin"))
        + glob.glob(os.path.join(D, f"d2_pos{pos-1}_*_logits.bin"))
    )
    if tps:
        ta = load(tps[-1])
        if ta.size >= 10000:
            tn = min(ta.size, n)
            ti = int(np.argmax(ta[:tn]))
            mxa, rms, _ = mx(a[:tn], ta[:tn])
            w(
                f"  vs d2_tf {os.path.basename(tps[-1])}: tf_arg={ti} maxAbs={mxa:.6e} "
                f"t315={ta[315]:.6f} t16895={ta[16895]:.6f}"
            )
        else:
            w(f"  vs d2_tf skip small n={ta.size} {os.path.basename(tps[-1])}")

w("")
w("=== layerwise eng@pos10 vs d2_tf@pos10 (forward of 23192 → tip2 logits) ===")
pairs = [
    ("ATTN_NORM", ["attn_norm"]),
    ("Q_PRE_ROPE", ["q"]),
    ("K_PRE_ROPE", ["k"]),
    ("V", ["v"]),
    ("Q_POST_ROPE", ["q"]),  # tf q is pre-rope; expect MIS if compared
    ("K_POST_ROPE", ["k"]),
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
    layer_first = None
    for ekey, names in pairs:
        if ekey in ("Q_POST_ROPE", "K_POST_ROPE"):
            continue  # skip false compares to pre-rope tf dumps
        ep = latest(f"{ekey}_{layer}", 10)
        tp = find_tf(10, layer, names)
        if ep is None or tp is None:
            continue
        mxa, rms, arg = mx(load(ep), load(tp))
        st = status(mxa)
        if layer < 3 or mxa >= 1e-4:
            w(
                f"L{layer} {ekey}: maxAbs={mxa:.6e} rms={rms:.6e} arg={arg} {st}"
            )
        if first is None and mxa >= 1e-4:
            first = (layer, ekey, mxa, rms)
            layer_first = ekey
    if first and layer > first[0] + 2:
        break

w("")
if first:
    w(
        f"FIRST_CLEAR_POST_F16 layer={first[0]} op={first[1]} "
        f"maxAbs={first[2]:.6e} rms={first[3]:.6e}"
    )
else:
    w("FIRST_CLEAR_POST_F16=NONE_IN_SCAN")

# Also pos0 L0 confirm F16 closed
w("")
w("=== confirm L0 pos0 F16 close ===")
for ekey, names in [
    ("V", ["v"]),
    ("ATTN_PRE_O", ["attn_out"]),
    ("FFN_INP", ["resid1"]),
    ("POST_FFN", ["resid2"]),
]:
    ep = latest(f"{ekey}_0", 0)
    tp = find_tf(0, 0, names)
    mxa, rms, _ = mx(load(ep), load(tp))
    w(f"pos0 L0 {ekey}: maxAbs={mxa:.6e} {status(mxa)}")

# Identity: PRE_O vs tile(F16(V)) at pos0 and pos10
w("")
w("=== PRE_O vs F16-tiled V identity ===")


def tile_f16(v, hd, nh, nkv):
    vf = v.astype(np.float16).astype(np.float32)
    gs = nh // nkv
    out = np.zeros(nh * hd, dtype=np.float32)
    for h in range(nh):
        kv = h // gs
        out[h * hd : (h + 1) * hd] = vf[kv * hd : (kv + 1) * hd]
    return out


for pos in [0, 10]:
    v = load(latest("V_0", pos))
    pre = load(latest("ATTN_PRE_O_0", pos))
    hd = 128
    nkv = v.size // hd
    nh = pre.size // hd
    mxa_f32, _, _ = mx(pre, tile_f16(v.astype(np.float32), hd, nh, nkv))  # wrong helper
    # proper f32 tile
    gs = nh // nkv
    t32 = np.zeros(nh * hd, dtype=np.float32)
    for h in range(nh):
        kv = h // gs
        t32[h * hd : (h + 1) * hd] = v[kv * hd : (kv + 1) * hd]
    tf16 = tile_f16(v, hd, nh, nkv)
    m32, _, _ = mx(pre, t32)
    m16, _, _ = mx(pre, tf16)
    w(f"pos{pos}: PRE vs tile(F32 V)={m32:.6e} PRE vs tile(F16 V)={m16:.6e} attend_id={pos+1}")

open(OUT, "w", encoding="utf-8").write("\n".join(lines) + "\n")
w(f"WROTE {OUT}")
