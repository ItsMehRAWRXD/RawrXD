# R91: trial-only scrub on FFN_NORM vs FA006 Q8. PROMOTE=0
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
    qs, xd = [], []
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
        d = np.float32(0)
        if amax != 0:
            iscale = np.float32(-127.0) / maxv
            d = np.float32(1.0) / iscale
            for j in range(256):
                v = nearest_int_q8k(float(iscale * np.float32(xi[j])))
                row[j] = 127 if v > 127 else v
        qs.append(row)
        xd.append(d)
    return qs, xd


def scrub(x, b):
    u = np.frombuffer(x.tobytes(), dtype=np.uint32).copy()
    u = u & np.uint32(0xFFFFFFFF ^ ((1 << b) - 1))
    return np.frombuffer(u.tobytes(), dtype=np.float32).copy()


def ulp(a, b):
    ai = struct.unpack("<I", struct.pack("<f", float(a)))[0]
    bi = struct.unpack("<I", struct.pack("<f", float(b)))[0]
    return abs(ai - bi)


fn_g = load(pick(gpu, "deep2_FFN_NORM_0_pos1", 2048))
fn_c = load(pick(ctrl, "deep2_FFN_NORM_0_pos1", 2048))
qc, xc = quant(fn_c)
print("raw", "qs", sum(int((a != b).sum()) for a, b in zip(quant(fn_g)[0], qc)))

for bits in range(0, 10):
    g2 = scrub(fn_g, bits) if bits else fn_g.copy()
    qg, xg = quant(g2)
    qs = sum(int((a != b).sum()) for a, b in zip(qg, qc))
    xd_u = max(ulp(xg[i], xc[i]) for i in range(8))
    print(
        f"norm_scrub{bits}: maxAbs_vs_ctrl={float(np.max(np.abs(g2 - fn_c))):.3e} "
        f"qs_diff={qs} max_xd_ulp={xd_u}"
    )

# sticky: snap trial to ctrl when within N ulp (oracle — needs ctrl)
for maxu in [1, 2, 4, 8, 16, 32]:
    g2 = fn_g.copy()
    ch = 0
    for i in range(len(g2)):
        if ulp(fn_g[i], fn_c[i]) <= maxu:
            if g2[i] != fn_c[i]:
                ch += 1
            g2[i] = fn_c[i]
    qg, xg = quant(g2)
    qs = sum(int((a != b).sum()) for a, b in zip(qg, qc))
    print(
        f"ulp_snap<={maxu}: changed={ch} qs={qs} "
        f"maxAbs={float(np.max(np.abs(g2 - fn_c))):.3e}"
    )
