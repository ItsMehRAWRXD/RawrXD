# R91 diag: FFN_NORM ULP -> GPU Q8 qs/xd vs FA006. PROMOTE=0
import os, re, struct
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_r90_bar")
ctrl = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_r89_ctrl_dp")


def pick(d, key, pn):
    hits = []
    for n in os.listdir(d):
        if not n.endswith(".bin") or key not in n:
            continue
        if re.search(r"_pos1\d_", n):
            continue
        if f"_n{pn}_" in n:
            hits.append(os.path.join(d, n))
    return sorted(hits)[-1] if hits else None


def load(p):
    return np.fromfile(p, dtype=np.float32)


def ulp(a, b):
    ai = struct.unpack("<I", struct.pack("<f", float(a)))[0]
    bi = struct.unpack("<I", struct.pack("<f", float(b)))[0]
    return abs(ai - bi)


def nearest_int_q8k(fval):
    val = np.float32(fval) + np.float32(12582912.0)
    bits = np.frombuffer(np.asarray([val], dtype=np.float32).tobytes(), dtype=np.uint32)[0]
    return int(bits & 0x007FFFFF) - 0x00400000


def quant_gpu(x):
    nblk = len(x) // 256
    qs = np.zeros((nblk, 256), np.int32)
    xd = np.zeros(nblk, np.float32)
    maxvs = np.zeros(nblk, np.float32)
    maxi = np.zeros(nblk, np.int32)
    for i in range(nblk):
        xi = x[i * 256 : (i + 1) * 256]
        amax = np.float32(0)
        maxv = np.float32(0)
        mj = -1
        for j in range(256):
            ax = np.abs(np.float32(xi[j]))
            if ax > amax:
                amax = ax
                maxv = np.float32(xi[j])
                mj = j
        maxvs[i] = maxv
        maxi[i] = mj
        if amax == 0:
            continue
        iscale = np.float32(-127.0) / maxv
        xd[i] = np.float32(1.0) / iscale
        for j in range(256):
            v = nearest_int_q8k(float(iscale * np.float32(xi[j])))
            qs[i, j] = 127 if v > 127 else v
    return xd, qs, maxvs, maxi


g = load(pick(gpu, "deep2_FFN_NORM_0_pos1", 2048))
c = load(pick(ctrl, "deep2_FFN_NORM_0_pos1", 2048))
xdg, qg, mg, ig = quant_gpu(g)
xdc, qc, mc, ic = quant_gpu(c)
print("FFN_NORM maxAbs", float(np.max(np.abs(g - c))), "@", int(np.argmax(np.abs(g - c))))
total_qs = 0
for i in range(8):
    nd = int((qg[i] != qc[i]).sum())
    total_qs += nd
    print(
        f"blk{i}: qs_diff={nd} idx_g={int(ig[i])} idx_c={int(ic[i])} "
        f"maxv_ulp={ulp(mg[i], mc[i])} xd_ulp={ulp(xdg[i], xdc[i])}"
    )
    if nd:
        for j in np.where(qg[i] != qc[i])[0][:6]:
            print(
                " ",
                int(j),
                "qg",
                int(qg[i, j]),
                "qc",
                int(qc[i, j]),
                "xg",
                float(g[i * 256 + j]),
                "xc",
                float(c[i * 256 + j]),
            )
print("TOTAL_QS_DIFF", total_qs)

# Counterfactual: force trial maxv to ctrl maxv (same idx assumed)
qs2 = np.zeros_like(qg)
for i in range(8):
    maxv = np.float32(mc[i])
    iscale = np.float32(-127.0) / maxv
    for j in range(256):
        v = nearest_int_q8k(float(iscale * np.float32(g[i * 256 + j])))
        qs2[i, j] = 127 if v > 127 else v
    nd = int((qs2[i] != qc[i]).sum())
    print(f"snap_maxv blk{i} qs_diff_vs_ctrl={nd}")

# FP16 roundtrip on FFN_INP
fi_g = load(pick(gpu, "deep2_FFN_INP_0_pos1", 2048))
fi_c = load(pick(ctrl, "deep2_FFN_INP_0_pos1", 2048))
fi_g16 = fi_g.astype(np.float16).astype(np.float32)
fi_c16 = fi_c.astype(np.float16).astype(np.float32)
print(
    "FFN_INP maxAbs",
    float(np.max(np.abs(fi_g - fi_c))),
    "after_f16 trial-ctrl",
    float(np.max(np.abs(fi_g16 - fi_c16))),
    "equal",
    bool(np.array_equal(fi_g16, fi_c16)),
    "f16_changes_trial_nz",
    int((fi_g16 != fi_g).sum()),
)

# ATTN_OUT hold tightness
ao_g = load(pick(gpu, "deep2_ATTN_OUT_0_pos1", 2048))
ao_c = load(pick(ctrl, "deep2_ATTN_OUT_0_pos1", 2048))
d = np.abs(ao_g - ao_c)
print(
    "ATTN_OUT maxAbs",
    float(d.max()),
    "@",
    int(d.argmax()),
    "nz",
    int((d > 0).sum()),
    "max_ulp",
    max(ulp(ao_g[i], ao_c[i]) for i in range(len(ao_g)) if d[i] > 0),
)
