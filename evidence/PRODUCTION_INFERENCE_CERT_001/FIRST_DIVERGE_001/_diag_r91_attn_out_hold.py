# R91: ATTN_OUT scrub -> FFN_INP -> FFN_NORM -> Q8 vs FA006. PROMOTE=0
import os, re, struct
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_r90_bar")
ctrl = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_r89_ctrl_dp")


def pick(d, key, pn):
    hits = [
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith(".bin")
        and key in n
        and f"_n{pn}_" in n
        and not re.search(r"_pos1\d_", n)
    ]
    return sorted(hits)[-1]


def load(p):
    return np.fromfile(p, dtype=np.float32)


def nearest_int_q8k(fval):
    val = np.float32(fval) + np.float32(12582912.0)
    bits = np.frombuffer(np.asarray([val], dtype=np.float32).tobytes(), dtype=np.uint32)[0]
    return int(bits & 0x007FFFFF) - 0x00400000


def quant(x):
    qs = []
    for i in range(len(x) // 256):
        xi = x[i * 256 : (i + 1) * 256]
        amax = np.float32(0)
        maxv = np.float32(0)
        for j in range(256):
            ax = np.abs(np.float32(xi[j]))
            if ax > amax:
                amax = ax
                maxv = np.float32(xi[j])
        row = np.zeros(256, np.int32)
        if amax != 0:
            iscale = np.float32(-127.0) / maxv
            for j in range(256):
                v = nearest_int_q8k(float(iscale * np.float32(xi[j])))
                row[j] = 127 if v > 127 else v
        qs.append(row)
    return qs


def scrub(x, b):
    if b <= 0:
        return x.copy()
    u = np.frombuffer(x.tobytes(), dtype=np.uint32).copy()
    u = u & np.uint32(0xFFFFFFFF ^ ((1 << b) - 1))
    return np.frombuffer(u.tobytes(), dtype=np.float32).copy()


ao_g = load(pick(gpu, "deep2_ATTN_OUT_0_pos1", 2048))
ao_c = load(pick(ctrl, "deep2_ATTN_OUT_0_pos1", 2048))
fi_g = load(pick(gpu, "deep2_FFN_INP_0_pos1", 2048))
fi_c = load(pick(ctrl, "deep2_FFN_INP_0_pos1", 2048))
fn_c = load(pick(ctrl, "deep2_FFN_NORM_0_pos1", 2048))
# xin = fi - ao (residual input before attn out add)
xin_g = fi_g - ao_g
xin_c = fi_c - ao_c
print("xin trial vs ctrl", float(np.max(np.abs(xin_g - xin_c))))

mean = float(np.dot(fi_c, fi_c) / len(fi_c))
inv = 1.0 / np.sqrt(mean + 1e-5)
w = np.zeros_like(fi_c)
for i in range(len(fi_c)):
    den = fi_c[i] * inv
    w[i] = fn_c[i] / den if abs(den) > 1e-20 else 0.0
qc = quant(fn_c)


def rn(x):
    m = float(np.dot(x, x) / len(x))
    invr = 1.0 / np.sqrt(m + 1e-5)
    return x * invr * w


for bits in range(0, 12):
    ao2 = scrub(ao_g, bits)
    fi2 = xin_g + ao2
    fn2 = rn(fi2)
    qs = sum(int((a != b).sum()) for a, b in zip(quant(fn2), qc))
    print(
        f"ao_scrub{bits}: ao_vs_ctrl={float(np.max(np.abs(ao2 - ao_c))):.3e} "
        f"fi_vs_ctrl={float(np.max(np.abs(fi2 - fi_c))):.3e} "
        f"fn_vs_ctrl={float(np.max(np.abs(fn2 - fn_c))):.3e} qs={qs}"
    )

# Replace trial ao with ctrl ao (oracle ATTN_OUT hold)
fi_o = xin_g + ao_c
# xin may differ?
print("oracle ao: xin was", float(np.max(np.abs(xin_g - xin_c))))
fn_o = rn(fi_o)
print(
    "oracle ATTN_OUT hold: fi",
    float(np.max(np.abs(fi_o - fi_c))),
    "fn",
    float(np.max(np.abs(fn_o - fn_c))),
    "qs",
    sum(int((a != b).sum()) for a, b in zip(quant(fn_o), qc)),
)
