# Offline FA on Q/K_POST_ROPE_1 + V_1 vs product PRE_O_1 (CLOSE_005).
# Must match product ~1e-6 before claiming owner. PROMOTE=0 — no invented PASS.
import math, os
import numpy as np

EV = os.path.dirname(os.path.abspath(__file__))
GPU = os.path.join(EV, "stage_dump_attn_pre_o_1_pos1_close005_postrope")
REF = os.path.join(EV, "stage_dump_ref_matched")
HD, NH, GS = 64, 32, 8
SCALE = float(np.float32(1.0 / np.sqrt(np.float32(HD))))


def load(p):
    return np.frombuffer(open(p, "rb").read(), dtype=np.float32).copy()


def f16(a):
    return a.astype(np.float16).astype(np.float32)


def mx(a, b):
    d = np.abs(a.astype(np.float64) - b.astype(np.float64))
    i = int(d.argmax())
    return float(d[i]), i, int((d > 1e-6).sum())


def pick(d, s):
    hits = [
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith(".bin") and s in n
    ]
    if not hits:
        raise FileNotFoundError(repr(s) + " in " + d)
    # Prefer full-width dumps (n2048 / n256) over head slices
    full = [h for h in hits if "_n2048_" in h or "_n256_" in h]
    return sorted(full if full else hits)[0]


def fa(q, k0, k1, v0, v1, q_f16=True, k_f16=True, v_f16=True, accum_f16=True):
    out = np.zeros(NH * HD, dtype=np.float32)
    for h in range(NH):
        kvh = h // GS
        qq = f16(q[h * HD : (h + 1) * HD]) if q_f16 else q[h * HD : (h + 1) * HD].astype(np.float32)
        ks = [
            f16(k0) if k_f16 else k0.astype(np.float32),
            f16(k1) if k_f16 else k1.astype(np.float32),
        ]
        vs = [
            f16(v0) if v_f16 else v0.astype(np.float32),
            f16(v1) if v_f16 else v1.astype(np.float32),
        ]
        M = -np.inf
        S = 0.0
        VKQ = np.zeros(HD, dtype=np.float16 if accum_f16 else np.float32)
        for ic in [0, 1]:
            s = float(np.dot(qq.astype(np.float32), ks[ic][kvh * HD : (kvh + 1) * HD]) * SCALE)
            Mold = M
            if s > M:
                M = s
                ms = 0.0 if Mold == -np.inf else math.exp(Mold - M)
                if accum_f16:
                    VKQ = (VKQ.astype(np.float32) * ms).astype(np.float16)
                else:
                    VKQ = VKQ.astype(np.float32) * ms
                vs_w = 1.0
            else:
                ms = 1.0
                vs_w = math.exp(s - M)
            vv = vs[ic][kvh * HD : (kvh + 1) * HD]
            if accum_f16:
                VKQ = (VKQ.astype(np.float32) + vv.astype(np.float32) * vs_w).astype(np.float16)
            else:
                VKQ = VKQ.astype(np.float32) + vv.astype(np.float32) * vs_w
            S = S * ms + vs_w
        out[h * HD : (h + 1) * HD] = VKQ.astype(np.float32) * (1.0 / S)
    return out


q = load(pick(GPU, "deep2_Q_POST_ROPE_1_pos1_"))
k0 = load(pick(GPU, "deep2_K_POST_ROPE_1_pos0_"))
k1 = load(pick(GPU, "deep2_K_POST_ROPE_1_pos1_"))
v0 = load(pick(GPU, "deep2_V_1_pos0_"))
v1 = load(pick(GPU, "deep2_V_1_pos1_"))
pre = load(pick(GPU, "deep2_ATTN_PRE_O_1_pos1_"))
lpre = load(pick(REF, "llama_ATTN_PRE_O_1_pos1_layer0_full_n2048_"))
lq = load(pick(REF, "llama_Q_POST_ROPE_1_pos1_layer0_full_n2048_"))
lk0 = load(pick(REF, "llama_K_POST_ROPE_1_pos0_layer0_full_n256_"))
lk1 = load(pick(REF, "llama_K_POST_ROPE_1_pos1_layer0_full_n256_"))
lv0 = load(pick(REF, "llama_V_1_pos0_layer0_full_n256_"))
lv1 = load(pick(REF, "llama_V_1_pos1_layer0_full_n256_"))

lines = []
lines.append(f"ops_Q {mx(q, lq)}")
lines.append(f"ops_K0 {mx(k0, lk0)}")
lines.append(f"ops_K1 {mx(k1, lk1)}")
lines.append(f"ops_V0 {mx(v0, lv0)}")
lines.append(f"ops_V1 {mx(v1, lv1)}")
lines.append(f"product vs REF {mx(pre, lpre)}")
fa_gpu = fa(q, k0, k1, v0, v1)
lines.append(f"FA(gpu POST_ROPE) vs product {mx(fa_gpu, pre)}")
lines.append(f"FA(gpu POST_ROPE) vs REF {mx(fa_gpu, lpre)}")
fa_ref = fa(lq, lk0, lk1, lv0, lv1)
lines.append(f"FA(ref POST_ROPE) vs REF {mx(fa_ref, lpre)}")
fa_refq = fa(lq, k0, k1, v0, v1)
lines.append(f"FA(refQ+gpuKV) vs product {mx(fa_refq, pre)}")
lines.append(f"FA(refQ+gpuKV) vs REF {mx(fa_refq, lpre)}")
# head11 cluster
h11 = slice(11 * HD, 12 * HD)
dprod = np.abs(pre.astype(np.float64) - lpre.astype(np.float64))
dfa = np.abs(fa_gpu.astype(np.float64) - pre.astype(np.float64))
drefq = np.abs(fa_refq.astype(np.float64) - lpre.astype(np.float64))
lines.append(
    f"head11 product_vs_REF maxAbs={float(dprod[h11].max()):.6e} "
    f"FA_vs_prod={float(dfa[h11].max()):.6e} "
    f"refQ_gpuKV_vs_REF={float(drefq[h11].max()):.6e}"
)
owner_ok = mx(fa_gpu, pre)[0] <= 1e-6
lines.append(f"FA_MATCHES_PRODUCT_1e6={int(owner_ok)}")
lines.append("PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0")
text = "\n".join(lines) + "\n"
outp = os.path.join(EV, "GPU_PARITY_ATTN_PRE_O_1_POS1_CLOSE_005.fa_diag.txt")
open(outp, "w", encoding="utf-8").write(text)
print(text)
print("WROTE", outp)
