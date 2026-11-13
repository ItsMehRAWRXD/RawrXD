#!/usr/bin/env python3
import glob
import os
import numpy as np

EV = r"F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039"
L = os.path.join(EV, "cpu_llama", "llama_tf")
D = os.path.join(EV, "cpu_llama", "d2_tf")
S = os.path.join(EV, "cpu_llama", "stage_engine")
out = os.path.join(EV, "cpu_llama", "CMP_TF_LOGITS.txt")


def load(p):
    return np.fromfile(p, dtype=np.float32)


lines = []


def w(s):
    lines.append(s)
    print(s)


w("TEACHER_FORCED tokens=7985 825 2805 11652 911 23192 16895 63762 13 576 23192")
w("COMPARE llama_tf vs deep2_parity_trace (d2_tf) logits/hidden")
w("FOCUS_IDS=315,16895,63762,576,23192")
focus = [315, 16895, 63762, 576, 23192, 151643]

first_argmax_mis = None
first_logit_maxabs = None
for pos in range(11):
    lp = os.path.join(L, f"ref_logits_pos{pos}.bin")
    dp = os.path.join(D, f"d2_logits_pos{pos}.bin")
    lh = os.path.join(L, f"ref_hidden_pos{pos}.bin")
    if not (os.path.exists(lp) and os.path.exists(dp)):
        w(f"pos={pos} MISSING llama={os.path.exists(lp)} d2={os.path.exists(dp)}")
        continue
    a = load(lp)
    b = load(dp)
    n = min(a.size, b.size)
    a = a[:n]
    b = b[:n]
    ai = int(np.argmax(a))
    bi = int(np.argmax(b))
    diff = np.abs(a - b)
    mx = float(diff.max())
    rms = float(np.sqrt(np.mean(diff * diff)))
    if first_argmax_mis is None and ai != bi:
        first_argmax_mis = pos
    if first_logit_maxabs is None and mx > 1e-3:
        first_logit_maxabs = pos
    foc = " ".join([f"{i}:{a[i]:.6f}/{b[i]:.6f}" for i in focus if i < n])
    w(
        f"pos={pos} llama_arg={ai} d2_arg={bi} match={int(ai==bi)} "
        f"maxAbs={mx:.6e} rms={rms:.6e} llama_max={a[ai]:.6f} d2_max={b[bi]:.6f}"
    )
    w(f"  focus {foc}")
    if os.path.exists(lh):
        h = load(lh)
        cands = sorted(glob.glob(os.path.join(D, f"d2_pos{pos}_*_out_norm.bin")))
        if not cands:
            cands = sorted(glob.glob(os.path.join(D, f"d2_pos{pos}_*_result_norm.bin")))
        if cands:
            dh = load(cands[0])
            m = min(h.size, dh.size)
            hd = np.abs(h[:m] - dh[:m])
            w(
                f"  hidden vs {os.path.basename(cands[0])} "
                f"maxAbs={hd.max():.6e} rms={np.sqrt(np.mean(hd*hd)):.6e}"
            )
        else:
            w(f"  hidden llama n={h.size} (no d2 out_norm bin found)")

w("")
w(f"FIRST_ARGMAX_MISMATCH_POS={first_argmax_mis}")
w(f"FIRST_LOGIT_MAXABS_GT_1e-3_POS={first_logit_maxabs}")

# Engine STAGE logits files
elog = sorted(glob.glob(os.path.join(S, "*LOGITS*")))
w(f"ENGINE_STAGE_LOGITS_FILES={len(elog)}")
for p in elog[:30]:
    w(f"  {os.path.basename(p)}")

a = load(os.path.join(L, "ref_logits_pos10.bin"))
b = load(os.path.join(D, "d2_logits_pos10.bin"))
w("")
w("POS10_DETAIL")
for i in [315, 16895, 63762, 821, 374]:
    w(f"  id={i} llama={a[i]:.9f} d2_tf={b[i]:.9f} delta={b[i]-a[i]:.9f}")
w(f"  margin_llama(16895-315)={a[16895]-a[315]:.9f}")
w(f"  margin_d2(16895-315)={b[16895]-b[315]:.9f}")

# Compare engine tip logits at decode pos for idx2 (pos10 after shared prefix)
# Prefer FINAL_LOGITS or LOGITS dumps tagged pos10 from second generate if present.
eng_logits = sorted(glob.glob(os.path.join(S, "deep2_LOGITS_*pos10*.bin")))
if not eng_logits:
    eng_logits = sorted(glob.glob(os.path.join(S, "*LOGITS*pos10*.bin")))
w(f"ENGINE_LOGITS_POS10_CANDS={len(eng_logits)}")
for p in eng_logits[-4:]:
    e = load(p)
    n = min(e.size, a.size)
    ei = int(np.argmax(e[:n]))
    d_l = np.abs(e[:n] - a[:n])
    d_d = np.abs(e[:n] - b[:n])
    w(
        f"  eng={os.path.basename(p)} arg={ei} vs_llama maxAbs={d_l.max():.6e} "
        f"vs_d2tf maxAbs={d_d.max():.6e} e315={e[315]:.6f} e16895={e[16895]:.6f}"
    )

open(out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("WROTE", out)
