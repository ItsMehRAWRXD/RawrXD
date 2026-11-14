# Offline FA head11 ablation on POST_ROPE_1 (CLOSE_005). PROMOTE=0.
import glob, math, os
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close005_postrope")
ref = os.path.join(ev, "stage_dump_ref_matched")
n_heads, n_kv, hd = 32, 4, 64


def pick(d, substr):
    hits = sorted(
        p
        for p in glob.glob(os.path.join(d, f"*{substr}*"))
        if p.endswith(".bin") and ("_n2048_" in p or "_n256_" in p)
    )
    return hits[0] if hits else None


def load(p):
    return np.fromfile(p, dtype=np.float32)


def f16rt(x):
    return float(np.float16(x).astype(np.float32))


def ulp_diff(a, b):
    ai = a.view(np.uint32).astype(np.int64)
    bi = b.view(np.uint32).astype(np.int64)
    return np.abs(ai - bi)


def fa(q, ks, vs, q_f16=True, k_f16=True, v_f16=True, accum_f16=True):
    scale = 1.0 / math.sqrt(hd)
    qv = np.array([f16rt(x) if q_f16 else float(x) for x in q], dtype=np.float64)
    vkq = np.zeros(hd, dtype=np.float64)
    M = -np.inf
    S = 0.0
    for k, v in zip(ks, vs):
        kk = np.array([f16rt(x) if k_f16 else float(x) for x in k], dtype=np.float64)
        vv = np.array([f16rt(x) if v_f16 else float(x) for x in v], dtype=np.float64)
        s = float(np.dot(qv, kk)) * scale
        Mold = M
        if s > M:
            M = s
            ms = 0.0 if Mold == -np.inf else math.exp(Mold - M)
            vs_ = 1.0
            if Mold != -np.inf:
                vkq *= ms
                if accum_f16:
                    vkq = np.array([f16rt(x) for x in vkq], dtype=np.float64)
        else:
            ms = 1.0
            vs_ = math.exp(s - M)
        add = vv * vs_
        if accum_f16:
            vkq = np.array(
                [f16rt(float(vkq[i] + add[i])) for i in range(hd)], dtype=np.float64
            )
        else:
            vkq = vkq + add
        S = S * ms + vs_
    invS = 0.0 if S == 0 else 1.0 / S
    if accum_f16:
        return np.array(
            [float(np.float16(vkq[i]).astype(np.float32)) * invS for i in range(hd)],
            dtype=np.float32,
        )
    return (vkq * invS).astype(np.float32)


def head_slice(t, h):
    return t[h * hd : (h + 1) * hd]


def kv_for_head(t, h):
    kv_h = h // (n_heads // n_kv)
    return t[kv_h * hd : (kv_h + 1) * hd]


gq = load(pick(gpu, "deep2_Q_POST_ROPE_1_pos1_"))
rq = load(pick(ref, "llama_Q_POST_ROPE_1_pos1_"))
gpre = load(pick(gpu, "deep2_ATTN_PRE_O_1_pos1_"))
rpre = load(pick(ref, "llama_ATTN_PRE_O_1_pos1_"))
gk0 = load(pick(gpu, "deep2_K_POST_ROPE_1_pos0_"))
gk1 = load(pick(gpu, "deep2_K_POST_ROPE_1_pos1_"))
gv0 = load(pick(gpu, "deep2_V_1_pos0_"))
gv1 = load(pick(gpu, "deep2_V_1_pos1_"))
rk0 = load(pick(ref, "llama_K_POST_ROPE_1_pos0_"))
rk1 = load(pick(ref, "llama_K_POST_ROPE_1_pos1_"))
rv0 = load(pick(ref, "llama_V_1_pos0_"))
rv1 = load(pick(ref, "llama_V_1_pos1_"))

d = np.abs(gpre - rpre)
print(
    f"PRODUCT PRE_O vs REF: maxAbs={d.max():.6e} @idx{int(d.argmax())} "
    f"head11={d[11*hd:12*hd].max():.6e}"
)
qd = np.abs(gq - rq)
u = ulp_diff(gq, rq)
print(
    f"Q_POST vs REF: maxAbs={qd.max():.6e} @idx{int(qd.argmax())} "
    f"head11_maxAbs={qd[11*hd:12*hd].max():.6e} head11_maxULP={int(u[11*hd:12*hd].max())}"
)
kd0 = np.abs(gk0 - rk0)
kd1 = np.abs(gk1 - rk1)
print(
    f"K_POST vs REF: k0 maxAbs={kd0.max():.6e} k1 maxAbs={kd1.max():.6e} "
    f"k1_head11(kv) maxAbs={kd1[2*hd:3*hd].max():.6e}"
)

cases = [
    ("gpuQ_gpuKV_F16", gq, gk0, gk1, gv0, gv1, dict(q_f16=True, accum_f16=True)),
    ("refQ_gpuKV_F16", rq, gk0, gk1, gv0, gv1, dict(q_f16=True, accum_f16=True)),
    ("gpuQ_refKV_F16", gq, rk0, rk1, rv0, rv1, dict(q_f16=True, accum_f16=True)),
    ("gpuQ_gpuKV_Qf32", gq, gk0, gk1, gv0, gv1, dict(q_f16=False, accum_f16=True)),
    (
        "gpuQ_gpuKV_F32acc",
        gq,
        gk0,
        gk1,
        gv0,
        gv1,
        dict(q_f16=True, accum_f16=False, k_f16=True, v_f16=True),
    ),
    (
        "gpuQ_gpuKV_allF32",
        gq,
        gk0,
        gk1,
        gv0,
        gv1,
        dict(q_f16=False, k_f16=False, v_f16=False, accum_f16=False),
    ),
    ("refQ_refKV_F16", rq, rk0, rk1, rv0, rv1, dict(q_f16=True, accum_f16=True)),
]

lines = []
for name, qsrc, k0, k1, v0, v1, opts in cases:
    out = np.zeros(n_heads * hd, dtype=np.float32)
    for h in range(n_heads):
        out[h * hd : (h + 1) * hd] = fa(
            head_slice(qsrc, h),
            [kv_for_head(k0, h), kv_for_head(k1, h)],
            [kv_for_head(v0, h), kv_for_head(v1, h)],
            **opts,
        )
    dd = np.abs(out - rpre)
    dp = np.abs(out - gpre)
    line = (
        f"{name}: vsREF maxAbs={dd.max():.6e} @idx{int(dd.argmax())} "
        f"head11={dd[11*hd:12*hd].max():.6e} vsPROD={dp.max():.6e}"
    )
    print(line)
    lines.append(line)

outp = os.path.join(ev, "GPU_PARITY_ATTN_PRE_O_1_POS1_CLOSE_005.ablate.txt")
open(outp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("WROTE", outp)
