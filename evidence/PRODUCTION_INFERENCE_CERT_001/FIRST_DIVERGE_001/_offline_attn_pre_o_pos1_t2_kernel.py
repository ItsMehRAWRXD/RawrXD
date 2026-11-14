# Offline T=2 AttentionWithCache vs llama kqv_out isolation (no EXE).
# Witness for GPU_PARITY_ATTN_PRE_O_POS1_T2_KERNEL_001. PROMOTE=0.
import math
import os
import numpy as np

EV = os.path.dirname(os.path.abspath(__file__))
GPU = os.path.join(EV, "stage_dump_attn_pre_o_product_wire")
REF = os.path.join(EV, "stage_dump_ref_matched")
HD, NH, GS = 64, 32, 8
SCALE = np.float32(1.0 / np.sqrt(np.float32(HD)))


def load(p):
    return np.frombuffer(open(p, "rb").read(), dtype=np.float32).copy()


def f16(a):
    return a.astype(np.float16).astype(np.float32)


def mx(a, b):
    d = np.abs(a.astype(np.float64) - b.astype(np.float64))
    i = int(d.argmax())
    return float(d[i]), i, int((d > 1e-6).sum())


def sdpa(q, k0, k1, v0, v1, kv_f16=True, out_f16=True):
    out = np.zeros(NH * HD, dtype=np.float32)
    kk0 = f16(k0) if kv_f16 else k0
    kk1 = f16(k1) if kv_f16 else k1
    vv0 = f16(v0) if kv_f16 else v0
    vv1 = f16(v1) if kv_f16 else v1
    for h in range(NH):
        kvh = h // GS
        qh = q[h * HD : (h + 1) * HD]
        s0 = float(np.dot(qh, kk0[kvh * HD : (kvh + 1) * HD]) * float(SCALE))
        s1 = float(np.dot(qh, kk1[kvh * HD : (kvh + 1) * HD]) * float(SCALE))
        m = max(s0, s1)
        e0, e1 = math.exp(s0 - m), math.exp(s1 - m)
        inv = 1.0 / (e0 + e1)
        o = (e0 * inv) * vv0[kvh * HD : (kvh + 1) * HD] + (e1 * inv) * vv1[
            kvh * HD : (kvh + 1) * HD
        ]
        out[h * HD : (h + 1) * HD] = f16(o) if out_f16 else o.astype(np.float32)
    return out


def main():
    q = load(os.path.join(GPU, "deep2_Q_POST_ROPE_0_pos1_layer0_full_n2048_seq070.bin"))
    k0 = load(os.path.join(GPU, "deep2_K_POST_ROPE_0_pos0_layer0_full_n256_seq011.bin"))
    k1 = load(os.path.join(GPU, "deep2_K_POST_ROPE_0_pos1_layer0_full_n256_seq071.bin"))
    v0 = load(os.path.join(GPU, "deep2_V_0_pos0_layer0_full_n256_seq003.bin"))
    v1 = load(os.path.join(GPU, "deep2_V_0_pos1_layer0_full_n256_seq063.bin"))
    pre = load(os.path.join(GPU, "deep2_ATTN_PRE_O_0_pos1_layer0_full_n2048_seq072.bin"))
    lq = load(os.path.join(REF, "llama_Q_POST_ROPE_0_pos1_layer0_full_n2048_seq010.bin"))
    lk0 = load(os.path.join(REF, "llama_K_POST_ROPE_0_pos0_layer0_full_n256_seq017.bin"))
    lk1 = load(os.path.join(REF, "llama_K_POST_ROPE_0_pos1_layer0_full_n256_seq020.bin"))
    lv0 = load(os.path.join(REF, "llama_V_0_pos0_layer0_full_n256_seq011.bin"))
    lv1 = load(os.path.join(REF, "llama_V_0_pos1_layer0_full_n256_seq012.bin"))
    lpre = load(os.path.join(REF, "llama_ATTN_PRE_O_0_pos1_layer0_full_n2048_seq060.bin"))

    print("ops", mx(q, lq), mx(k0, lk0), mx(k1, lk1), mx(v0, lv0), mx(v1, lv1))
    print("PRE product vs REF", mx(pre, lpre))
    o = sdpa(q, k0, k1, v0, v1)
    print("SDPA_gpu vs product", mx(o, pre), "vs REF", mx(o, lpre))
    oR = sdpa(lq, lk0, lk1, lv0, lv1)
    print("SDPA_ref vs REF", mx(oR, lpre), "vs product", mx(oR, pre))
    o2 = sdpa(lq, lk0, lk1, lv0, lv1, out_f16=False)
    print("SDPA_ref nof16out vs REF", mx(o2, lpre))
    # oracle convex floor on worst head (8)
    rh = lpre.reshape(32, 64)[8]
    v0h = f16(lv0).reshape(4, 64)[1]
    v1h = f16(lv1).reshape(4, 64)[1]
    best = 1e9
    for i in range(100001):
        w = i / 100000.0
        err = float(np.max(np.abs(f16(w * v0h + (1.0 - w) * v1h) - rh)))
        if err < best:
            best = err
    print("oracle_convex_floor_h8", best)
    print("ROOT_CAUSE_CLEAR=1 IRREDUCIBLE_HOST_SDPA=1 maxAbs=2.292544e-05 PROMOTE=0")


if __name__ == "__main__":
    main()
