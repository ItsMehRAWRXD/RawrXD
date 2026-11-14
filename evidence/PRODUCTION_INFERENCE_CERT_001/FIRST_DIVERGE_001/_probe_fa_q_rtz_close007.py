# CLOSE_007: offline FA with round-toward-zero Q F16 packing. PROMOTE=0
import os, math, struct
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close006_fa")
ref = os.path.join(ev, "stage_dump_ref_matched")
hd = 64


def load(p):
    return np.fromfile(p, dtype=np.float32)


def f16_rne(x):
    return float(np.float16(x).astype(np.float32))


def f16_rtz(x):
    # truncate mantissa toward zero via numpy float16 round mode unavailable;
    # emulate: encode with std, then if rne moved away from 0 vs trunc, step back.
    x = np.float32(x)
    h = np.float16(x)
    y = np.float32(h)
    # If RNE rounded away from zero relative to x, use nextafter toward zero in f16 space.
    if (float(x) > 0 and float(y) > float(x)) or (float(x) < 0 and float(y) < float(x)):
        bits = int(np.array([h], dtype=np.float16).view(np.uint16)[0])
        sign = bits & 0x8000
        mag = bits & 0x7FFF
        if mag > 0:
            mag -= 1
        bits = sign | mag
        y = np.float32(np.array([bits], dtype=np.uint16).view(np.float16)[0])
    return float(y)


def pick(d, pref, n="_n2048_"):
    hits = sorted(
        os.path.join(d, n_)
        for n_ in os.listdir(d)
        if n_.startswith(pref) and n_.endswith(".bin") and n in n_
    )
    if not hits and n == "_n2048_":
        hits = sorted(
            os.path.join(d, n_)
            for n_ in os.listdir(d)
            if n_.startswith(pref) and n_.endswith(".bin") and "_n256_" in n_
        )
    return hits[0]


def fa(q, ks, vs, q_pack):
    scale = 1.0 / math.sqrt(hd)
    qv = np.array([q_pack(x) for x in q], dtype=np.float64)
    vkq = np.zeros(hd, dtype=np.float64)
    M = -np.inf
    S = 0.0
    for k, v in zip(ks, vs):
        kk = np.array([f16_rne(x) for x in k], dtype=np.float64)
        vv = np.array([f16_rne(x) for x in v], dtype=np.float64)
        s = float(np.dot(qv, kk)) * scale
        Mold = M
        if s > M:
            M = s
            ms = 0.0 if Mold == -np.inf else math.exp(Mold - M)
            vs_ = 1.0
            if Mold != -np.inf:
                vkq *= ms
                vkq = np.array([f16_rne(x) for x in vkq], dtype=np.float64)
        else:
            ms = 1.0
            vs_ = math.exp(s - M)
        add = vv * vs_
        vkq = np.array(
            [f16_rne(float(vkq[i] + add[i])) for i in range(hd)], dtype=np.float64
        )
        S = S * ms + vs_
    invS = 0.0 if S == 0 else 1.0 / S
    return np.array(
        [float(np.float16(vkq[i]).astype(np.float32)) * invS for i in range(hd)],
        dtype=np.float32,
    )


print("idx747 pack RNE", f16_rne(-1.5200197697), "RTZ", f16_rtz(-1.5200197697))
print("idx747 ref pack RNE", f16_rne(-1.5200195312))

for layer, qp, k0p, k1p, v0p, v1p, prep, rq_override in [
    (
        1,
        "deep2_Q_POST_ROPE_1_pos1_",
        "deep2_K_POST_ROPE_1_pos0_",
        "deep2_K_POST_ROPE_1_pos1_",
        "deep2_V_1_pos0_",
        "deep2_V_1_pos1_",
        "deep2_ATTN_PRE_O_1_pos1_",
        os.path.join(ref, "llama_Q_POST_ROPE_1_pos1_layer0_full_n2048_seq102.bin"),
    ),
    (
        0,
        "deep2_Q_POST_ROPE_0_pos1_",
        "deep2_K_POST_ROPE_0_pos0_",
        "deep2_K_POST_ROPE_0_pos1_",
        "deep2_V_0_pos0_",
        "deep2_V_0_pos1_",
        "deep2_ATTN_PRE_O_0_pos1_",
        None,
    ),
]:
    gq = load(pick(gpu, qp))
    gpre = load(pick(gpu, prep))
    rpre = load(pick(ref, prep.replace("deep2", "llama")))
    gk0 = load(pick(gpu, k0p, "_n256_"))
    gk1 = load(pick(gpu, k1p, "_n256_"))
    gv0 = load(pick(gpu, v0p, "_n256_"))
    gv1 = load(pick(gpu, v1p, "_n256_"))
    out_rne = np.zeros(2048, np.float32)
    out_rtz = np.zeros(2048, np.float32)
    for h in range(32):
        kvh = h // 8
        ks = [gk0[kvh * 64 : (kvh + 1) * 64], gk1[kvh * 64 : (kvh + 1) * 64]]
        vs = [gv0[kvh * 64 : (kvh + 1) * 64], gv1[kvh * 64 : (kvh + 1) * 64]]
        out_rne[h * 64 : (h + 1) * 64] = fa(gq[h * 64 : (h + 1) * 64], ks, vs, f16_rne)
        out_rtz[h * 64 : (h + 1) * 64] = fa(gq[h * 64 : (h + 1) * 64], ks, vs, f16_rtz)
    print(
        f"L{layer} RNE vsREF={np.abs(out_rne - rpre).max():.6e} "
        f"h11={np.abs(out_rne - rpre)[704:768].max():.6e}"
    )
    print(
        f"L{layer} RTZ vsREF={np.abs(out_rtz - rpre).max():.6e} "
        f"h11={np.abs(out_rtz - rpre)[704:768].max():.6e} "
        f"vsPROD={np.abs(out_rtz - gpre).max():.6e}"
    )

print("PROMOTE=0")
