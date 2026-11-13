#!/usr/bin/env python3
"""Isolate first L0 attn op after V MATCH at pos0 (and tip pos feeding idx2)."""
import glob
import os
import re
import numpy as np

EV = r"F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039\cpu_llama"
S = os.path.join(EV, "batch04_final", "stage_engine")
D = os.path.join(EV, "d2_tf")
OUT = os.path.join(EV, "BISECT_L0_ATTN_AFTER_V.txt")

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


def latest(key, pos, stage_dir=S):
    files = [
        f
        for f in glob.glob(os.path.join(stage_dir, f"deep2_{key}_pos{pos}_*.bin"))
        if f.endswith(".bin")
    ]

    def seq(f):
        m = re.search(r"_seq(\d+)\.bin$", f)
        return int(m.group(1)) if m else -1

    files.sort(key=seq)
    return files[-1] if files else None


def tile_v(v, head_dim, n_h, n_kv):
    gs = n_h // n_kv
    out = np.zeros(n_h * head_dim, dtype=np.float32)
    for h in range(n_h):
        kv = h // gs
        out[h * head_dim : (h + 1) * head_dim] = v[kv * head_dim : (kv + 1) * head_dim]
    return out


def status(m):
    if m < 1e-6:
        return "MATCH"
    if m < 1e-4:
        return "NEAR"
    return "MISMATCH"


w("BISECT L0_ATTN_AFTER_V — eng batch04_final vs d2_tf")
w("FAIL_CLOSED · DO_NOT_REOPEN_Q4K_ACT=1 · PROMOTE=0")
w("")

for pos in [0, 10, 11]:
    w(f"=== pos={pos} ===")
    pairs = [
        ("ATTN_NORM_0", "attn_norm"),
        ("Q_PRE_ROPE_0", "q"),
        ("Q_POST_ROPE_0", "q"),  # tf q may be post-rope depending on dump point
        ("K_PRE_ROPE_0", "k"),
        ("K_POST_ROPE_0", "k"),
        ("V_0", "v"),
        ("ATTN_PRE_O_0", "attn_out"),
        ("ATTN_OUT_0", "attn_proj"),
        ("FFN_INP_0", "resid1"),
        ("POST_FFN_0", "resid2"),
    ]
    first = None
    for ekey, tname in pairs:
        ep = latest(ekey, pos)
        tps = sorted(glob.glob(os.path.join(D, f"d2_pos{pos}_blk0_*_{tname}.bin")))
        if ep is None or not tps:
            w(f"  {ekey} vs {tname}: MISSING eng={ep is not None} tf={bool(tps)}")
            continue
        ea, ta = load(ep), load(tps[0])
        mxa, rms, arg = mx(ea, ta)
        st = status(mxa)
        w(
            f"  {ekey} vs {tname}: n={min(ea.size, ta.size)} maxAbs={mxa:.6e} "
            f"rms={rms:.6e} arg={arg} {st} eng={os.path.basename(ep)}"
        )
        if first is None and mxa >= 1e-4:
            first = (ekey, tname, mxa, rms)
    if first:
        w(
            f"  FIRST_CLEAR pos={pos}: {first[0]} vs {first[1]} "
            f"maxAbs={first[2]:.6e} rms={first[3]:.6e}"
        )
    w("")

# Detailed pos0 identity checks
w("=== pos0 identity: attn·V @ attend=1 should equal GQA-tiled V ===")
v = load(latest("V_0", 0))
pre = load(latest("ATTN_PRE_O_0", 0))
hd = 128
n_kv = v.size // hd
n_h = pre.size // hd
w(f"headDim={hd} nKV={n_kv} nH={n_h} group={n_h // n_kv}")
tv = tile_v(v, hd, n_h, n_kv)
mxa, rms, arg = mx(pre, tv)
w(f"eng PRE_O vs tile(eng V): maxAbs={mxa:.6e} rms={rms:.6e} arg={arg} {status(mxa)}")
d = np.abs(pre.astype(np.float64) - tv.astype(np.float64)).reshape(n_h, hd)
w("  per-head maxAbs PRE vs tileV: " + ", ".join(f"{float(d[h].max()):.3e}" for h in range(n_h)))

tf_v = load(os.path.join(D, "d2_pos0_blk0_pc5_v.bin"))
tf_ao = load(os.path.join(D, "d2_pos0_blk0_pc6_attn_out.bin"))
tf_ap = load(os.path.join(D, "d2_pos0_blk0_pc7_attn_proj.bin"))
tf_r1 = load(os.path.join(D, "d2_pos0_blk0_pc8_resid1.bin"))
tf_ri = load(os.path.join(D, "d2_pos0_blk0_pc1_resid_in.bin"))
mxa, rms, arg = mx(tf_ao, tile_v(tf_v, hd, n_h, n_kv))
w(f"tf  attn_out vs tile(tf V): maxAbs={mxa:.6e} rms={rms:.6e} arg={arg} {status(mxa)}")
mxa, rms, arg = mx(v, tf_v)
w(f"eng V vs tf V: maxAbs={mxa:.6e} rms={rms:.6e} {status(mxa)}")
mxa, rms, arg = mx(pre, tf_ao)
w(f"eng PRE_O vs tf attn_out: maxAbs={mxa:.6e} rms={rms:.6e} {status(mxa)}")
mxa, rms, arg = mx(tv, tf_ao)
w(f"eng tile(V) vs tf attn_out: maxAbs={mxa:.6e} rms={rms:.6e} {status(mxa)}")

# Infer eng O-proj: FFN_INP = resid_in + attn_proj
ffn = load(latest("FFN_INP_0", 0))
# Prefer eng resid if available; else tf resid_in (pos0 embed MATCH expected)
eng_o = ffn.astype(np.float64) - tf_ri.astype(np.float64)
mxa, rms, arg = mx(eng_o.astype(np.float32), tf_ap)
w(f"inferred eng O (FFN_INP-tf_resid_in) vs tf attn_proj: maxAbs={mxa:.6e} rms={rms:.6e} {status(mxa)}")
mxa, rms, arg = mx(ffn, tf_r1)
w(f"eng FFN_INP vs tf resid1: maxAbs={mxa:.6e} rms={rms:.6e} {status(mxa)}")

w("")
w("FIRST8 eng V     " + " ".join(f"{x:.6g}" for x in v[:8]))
w("FIRST8 tf  V     " + " ".join(f"{x:.6g}" for x in tf_v[:8]))
w("FIRST8 eng PRE_O " + " ".join(f"{x:.6g}" for x in pre[:8]))
w("FIRST8 tf  ao    " + " ".join(f"{x:.6g}" for x in tf_ao[:8]))
w("FIRST8 eng tileV " + " ".join(f"{x:.6g}" for x in tv[:8]))

# Name controlling op
w("")
pre_vs_tile = mx(pre, tv)[0]
pre_vs_tf = mx(pre, tf_ao)[0]
if pre_vs_tile >= 1e-4:
    w(
        f"NEXT_CONTROLLING_OP=L0_ATTN_WEIGHTED_V (pos0 attend=1 but PRE_O!=tile(V) "
        f"maxAbs={pre_vs_tile:.6e}) — scores/softmax/AV or KV-read path"
    )
elif pre_vs_tf >= 1e-4:
    w(
        f"NEXT_CONTROLLING_OP=L0_ATTN_OUT_LAYOUT (PRE_O==tile(eng V) but != tf attn_out "
        f"maxAbs={pre_vs_tf:.6e}) — layout/GQA tiling disagreement"
    )
else:
    o_gap = mx(eng_o.astype(np.float32), tf_ap)[0]
    w(
        f"NEXT_CONTROLLING_OP=L0_O_PROJ (PRE_O MATCH; inferred O gap maxAbs={o_gap:.6e})"
    )

open(OUT, "w", encoding="utf-8").write("\n".join(lines) + "\n")
w(f"WROTE {OUT}")
