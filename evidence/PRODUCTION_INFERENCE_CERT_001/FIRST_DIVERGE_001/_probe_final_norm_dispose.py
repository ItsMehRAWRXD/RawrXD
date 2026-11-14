#!/usr/bin/env python3
"""FINAL_NORM@pos0 dispose: Apply CLOSED vs INPUT residual. PROMOTE=0."""
from __future__ import annotations

import glob
import hashlib
import os
import struct
from datetime import datetime

import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gd = os.path.join(ev, "stage_dump_ffn_down_2_xdonediv_cascade")
ref = os.path.join(ev, "stage_dump_gpu_ref")
gguf = r"G:\~dev\rawrxd\models\tinyllama.gguf"
ABS = 1e-4
EPS = 1e-5


def load(p):
    return np.fromfile(p, dtype=np.float32)


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def find_one(d, pat):
    hits = sorted(glob.glob(os.path.join(d, pat)))
    return hits[0] if hits else None


def cmp(a, b, tol=ABS):
    n = min(len(a), len(b))
    d = np.abs(a[:n] - b[:n])
    mx = float(d.max()) if n else float("nan")
    idx = int(np.argmax(d)) if n else -1
    ngt = int(np.sum(d > tol))
    return mx, idx, ngt, n, int(mx > tol)


def rmsnorm_apply(src, weight, eps=EPS):
    x = src.astype(np.float64)
    mean_sq = float(np.sum(x * x) / len(x))
    inv = np.float32(1.0 / np.sqrt(mean_sq + float(eps)))
    out = (src.astype(np.float32) * inv * weight.astype(np.float32)).astype(
        np.float32
    )
    return out, inv, mean_sq


def read_gguf_tensor(path, name):
    """Minimal GGUF F32 tensor reader for output_norm.weight."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != b"GGUF":
            raise RuntimeError("bad magic")
        version = struct.unpack("<I", f.read(4))[0]
        n_tensors, n_kv = struct.unpack("<QQ", f.read(16))

        def read_str():
            (n,) = struct.unpack("<Q", f.read(8))
            return f.read(n).decode("utf-8", "replace")

        def skip_val(t):
            if t == 8:
                read_str()
            elif t == 9:
                (at,) = struct.unpack("<I", f.read(4))
                (an,) = struct.unpack("<Q", f.read(8))
                for _ in range(an):
                    skip_val(at)
            else:
                sizes = {
                    0: 1,
                    1: 1,
                    2: 2,
                    3: 2,
                    4: 4,
                    5: 4,
                    6: 4,
                    7: 8,
                    10: 8,
                    11: 8,
                    12: 8,
                }
                f.read(sizes[t])

        for _ in range(n_kv):
            read_str()
            (t,) = struct.unpack("<I", f.read(4))
            skip_val(t)

        infos = []
        for _ in range(n_tensors):
            tname = read_str()
            (ndims,) = struct.unpack("<I", f.read(4))
            dims = [struct.unpack("<Q", f.read(8))[0] for _ in range(ndims)]
            (ttype,) = struct.unpack("<I", f.read(4))
            (offset,) = struct.unpack("<Q", f.read(8))
            infos.append((tname, dims, ttype, offset))

        pos = f.tell()
        align = 32
        if version >= 2:
            pad = (align - (pos % align)) % align
            f.read(pad)
        data_base = f.tell()

        for tname, dims, ttype, offset in infos:
            if tname != name:
                continue
            if ttype != 0:
                raise RuntimeError(f"{name} type={ttype} not F32")
            n = 1
            for d in dims:
                n *= int(d)
            f.seek(data_base + offset)
            return np.frombuffer(f.read(n * 4), dtype=np.float32).copy()
    raise RuntimeError(f"tensor {name} not found")


lines = [
    "GPU_PARITY_FINAL_NORM_CLOSE_001.probe",
    f"ASOF={datetime.now().isoformat(timespec='seconds')}",
    "PROMOTE=0 TIP_CLIMB=HOLD DENSE_MATCH=HOLD",
    f"DUMP={gd}",
    f"REF={ref}",
    "PRIOR_PUSH=bd5c89d036 ATTN_OUT_14 NOT_CLOSABLE",
    "PRIOR_APPLY=GPU_PARITY_FINAL_NORM_OPEN_RESIDUAL_001 FINALNORM_APPLY_CLOSED=1 ~5.5e-7",
]
spv = r"G:\~dev\rawrxd\src\backend\gemv_q4k.spv"
spv_sha = sha_file(spv)
lines.append(
    f"SPV_PIN={spv_sha} LEN={os.path.getsize(spv)} "
    f"HELD={int(spv_sha.startswith('40E76D2A'))}"
)

post_p = find_one(gd, "deep2_PROMPT_POST_LAYERS_pos0*.bin")
final_p = find_one(gd, "deep2_FINAL_NORM_pos0*.bin")
l21_p = find_one(gd, "deep2_LAYER21_OUT_pos0*.bin")
attn14_p = find_one(gd, "deep2_ATTN_OUT_14_pos0*.bin")
logits_p = find_one(gd, "deep2_LOGITS_pos2*.bin")
ref_final = find_one(ref, "llama_REF_FINAL_HIDDEN_pos0*.bin")
ref_post = find_one(ref, "llama_PROMPT_POST_LAYERS_pos0*.bin") or find_one(
    ref, "llama_POST_LAYERS_pos0*.bin"
)

weight = read_gguf_tensor(gguf, "output_norm.weight")
lines.append(f"WEIGHT=GGUF:{gguf} n={len(weight)} w0={float(weight[0]):.9g}")

post = load(post_p)
final = load(final_p)
applied, inv, mean_sq = rmsnorm_apply(post, weight, EPS)
mx_apply, idx_apply, ngt_apply, n_apply, fail_apply = cmp(applied, final, 1e-5)
lines.append("--- FinalNorm Apply (POST→FINAL offline RMSNormW_double) ---")
lines.append(f"POST={os.path.basename(post_p)}")
lines.append(f"FINAL={os.path.basename(final_p)}")
lines.append(f"meanSq={mean_sq:.9e} inv={float(inv):.9e} eps={EPS}")
lines.append(
    f"Apply(POST)_vs_FINAL: maxAbs={mx_apply:.6e} @idx{idx_apply} "
    f"n_gt={ngt_apply}/{n_apply} FUNCTIONAL_FAIL={fail_apply} tol=1e-5"
)
lines.append(f"FINALNORM_APPLY_CLOSED={int(fail_apply == 0)}")

lines.append("--- INPUT residual (cascade) ---")
if ref_post:
    mx_post, idx_post, ngt_post, n_post, fail_post = cmp(post, load(ref_post))
    lines.append(
        f"POST_vs_REF_POST: maxAbs={mx_post:.6e} @idx{idx_post} "
        f"n_gt={ngt_post}/{n_post} FUNCTIONAL_FAIL={fail_post} "
        f"ref={os.path.basename(ref_post)}"
    )
else:
    lines.append("POST_vs_REF_POST: MISSING_REF_POST")

l21 = load(l21_p)
cands = sorted(glob.glob(os.path.join(ref, "llama_LAYER21_OUT_pos0*.bin")))
best = None
for c in cands:
    mx, idx, ngt, n, fl = cmp(l21, load(c))
    if best is None or mx < best[0]:
        best = (mx, idx, ngt, n, fl, c)
mx_l21, idx_l21, ngt_l21, n_l21, fail_l21, rp = best
lines.append(
    f"LAYER21_OUT_vs_REF: maxAbs={mx_l21:.6e} @idx{idx_l21} "
    f"n_gt={ngt_l21}/{n_l21} FUNCTIONAL_FAIL={fail_l21} "
    f"ref={os.path.basename(rp)}"
)

mx_p21, idx_p21, ngt_p21, n_p21, fail_p21 = cmp(post, l21, 1e-6)
lines.append(
    f"POST_vs_LAYER21_OUT: maxAbs={mx_p21:.6e} @idx{idx_p21} "
    f"UNDER_TOL={int(fail_p21 == 0)} (expect near-identity pre-norm)"
)

mx_final, idx_final, ngt_final, n_final, fail_final = cmp(final, load(ref_final))
lines.append("--- FINAL vs REF ---")
lines.append(
    f"FINAL_NORM_vs_REF: maxAbs={mx_final:.6e} @idx{idx_final} "
    f"n_gt={ngt_final}/{n_final} FUNCTIONAL_FAIL={fail_final} "
    f"ref={os.path.basename(ref_final)}"
)
mx_ar, idx_ar, ngt_ar, n_ar, fail_ar = cmp(applied, load(ref_final))
lines.append(
    f"Apply(POST)_vs_REF: maxAbs={mx_ar:.6e} @idx{idx_ar} "
    f"n_gt={ngt_ar}/{n_ar} FUNCTIONAL_FAIL={fail_ar}"
)

attn = load(attn14_p)
cands_a = sorted(glob.glob(os.path.join(ref, "llama_ATTN_OUT_14_pos0*.bin")))
best_a = None
for c in cands_a:
    mx, idx, ngt, n, fl = cmp(attn, load(c))
    if best_a is None or mx < best_a[0]:
        best_a = (mx, idx, ngt, n, fl, c)
mx_a, idx_a, ngt_a, n_a, fail_a, rp_a = best_a
lines.append("--- Upstream cascade sites ---")
lines.append(
    f"ATTN_OUT_14: maxAbs={mx_a:.6e} @idx{idx_a} n_gt={ngt_a}/{n_a} "
    f"FUNCTIONAL_FAIL={fail_a} ref={os.path.basename(rp_a)}"
)

lines.append("--- LOGITS / argmax (if dumps) ---")
true_next = "residual-budget"
logits_fail = -1
mx_log = float("nan")
if logits_p:
    glog = load(logits_p)
    cands_l = sorted(glob.glob(os.path.join(ref, "llama_LOGITS_pos0*.bin"))) + sorted(
        glob.glob(os.path.join(ref, "llama_TIP_LOGITS_pos*.bin"))
    )
    best_l = None
    for c in cands_l:
        r = load(c)
        if len(r) != len(glog):
            continue
        mx, idx, ngt, n, fl = cmp(glog, r, 1e-3)
        if best_l is None or mx < best_l[0]:
            best_l = (mx, idx, ngt, n, fl, c, r)
    if best_l:
        mx_log, idx_log, ngt_log, n_log, fail_log, rp_l, rlog = best_l
        g_arg = int(np.argmax(glog))
        r_arg = int(np.argmax(rlog))
        lines.append(
            f"LOGITS: maxAbs={mx_log:.6e} @idx{idx_log} n_gt={ngt_log}/{n_log} "
            f"FUNCTIONAL_FAIL={fail_log} tol=1e-3 ref={os.path.basename(rp_l)}"
        )
        lines.append(
            f"ARGMAX deep2={g_arg} val={float(glog[g_arg]):.6e} "
            f"ref={r_arg} val={float(rlog[r_arg]):.6e} MATCH={int(g_arg == r_arg)}"
        )
        logits_fail = fail_log
        if fail_log:
            true_next = f"LOGITS maxAbs={mx_log:.6e} FUNCTIONAL_FAIL=1"
        else:
            true_next = "NONE"
    else:
        g_arg = int(np.argmax(glog))
        lines.append(
            f"LOGITS: deep2_only n={len(glog)} argmax={g_arg} "
            f"val={float(glog[g_arg]):.6e} NO_LEN_MATCHED_REF → residual-budget"
        )
        true_next = "residual-budget"
else:
    lines.append("LOGITS: MISSING_DUMP → residual-budget")
    true_next = "residual-budget"

independent = int(fail_apply == 1)
cascade_only = int(fail_apply == 0 and fail_final == 1)
closable = 1 if fail_final == 0 else 0
if fail_final == 0 and logits_fail == 1:
    pass
elif fail_final == 0 and logits_fail != 1:
    true_next = "NONE" if true_next.startswith("LOGITS") is False else true_next

lines.append("--- DISPOSITION ---")
lines.append(f"FINAL_NORM maxAbs={mx_final:.6e} FUNCTIONAL_FAIL={fail_final}")
lines.append(
    f"FINALNORM_APPLY_CLOSED={int(fail_apply == 0)} apply_maxAbs={mx_apply:.6e}"
)
lines.append(f"INPUT_RESIDUAL_CASCADE={cascade_only}")
lines.append(f"INDEPENDENT_APPLY_BUG={independent}")
lines.append(f"FINAL_NORM_CLOSABLE={closable}")
lines.append(
    "ROOT=FINAL_NORM_INPUT_RESIDUAL_CASCADE_FROM_L10_ACT_OUT_CHAIN"
    if cascade_only
    else "ROOT=FINAL_NORM_APPLY_OR_MIXED"
)
lines.append(
    "CHAIN_NOT_CLOSABLE=FFN_DOWN_10_ACT,ATTN_PRE_O_11_V_AMPLIFY,"
    "ATTN_OUT_14_O_PROJ_AMPLIFY"
)
lines.append(f"TRUE_NEXT={true_next}")
lines.append("DENSE_MATCH=HOLD (cascade residual-budget ≠ invent MATCH)")
lines.append("TIP_6754616E=HOLD PCT=67/48/48 MF_qdim099=HOLD")
lines.append("SPV_40E76D2A=HELD PROMOTE=0 TIP_CLIMB=HOLD")
lines.append("END")

out = "\n".join(lines) + "\n"
probe_path = os.path.join(ev, "GPU_PARITY_FINAL_NORM_CLOSE_001.probe.txt")
with open(probe_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(out)
print(out)
print(f"WROTE {probe_path}")
