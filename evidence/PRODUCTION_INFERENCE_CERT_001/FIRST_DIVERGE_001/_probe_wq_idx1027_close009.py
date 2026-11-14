# CLOSE_009: offline WQ kernels @idx1027 (head16 rope partner) + hold @747.
# PROMOTE=0 INVENT_PASS=0 — numeric probe only.
import os, struct
import numpy as np
from gguf import GGUFReader

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close008_hybridb")
ref = os.path.join(ev, "stage_dump_ref_matched")


def load(p):
    return np.fromfile(p, dtype=np.float32)


def pick(d, pref):
    hits = sorted(
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.startswith(pref) and n.endswith(".bin") and "_n2048_" in n
    )
    return hits[0]


def nearest_int_q8k(fval):
    val = np.float32(fval) + np.float32(12582912.0)
    bits = int(val.view(np.uint32))
    return (bits & 0x007FFFFF) - 0x00400000


def quantize_row_q8_K(x):
    nb = len(x) // 256
    qs = np.zeros(len(x), dtype=np.int8)
    bsums = np.zeros(nb * 16, dtype=np.int16)
    ds = np.zeros(nb, dtype=np.float32)
    for i in range(nb):
        xi = x[i * 256 : (i + 1) * 256]
        amax = 0.0
        maxv = 0.0
        for j in range(256):
            ax = abs(float(xi[j]))
            if ax > amax:
                amax = ax
                maxv = float(xi[j])
        if amax == 0:
            continue
        iscale = np.float32(-127.0 / np.float32(maxv))
        for j in range(256):
            v = nearest_int_q8k(float(iscale * np.float32(xi[j])))
            qs[i * 256 + j] = 127 if v > 127 else v
        for j in range(16):
            bsums[i * 16 + j] = int(
                qs[i * 256 + j * 16 : i * 256 + (j + 1) * 16].astype(np.int32).sum()
            )
        ds[i] = np.float32(1.0) / iscale
    return qs, bsums, ds


def f16_to_f32(h):
    return float(np.array([h], dtype=np.uint16).view(np.float16).astype(np.float32)[0])


def ulp(a, b):
    return abs(int(np.float32(a).view(np.uint32)) - int(np.float32(b).view(np.uint32)))


def bits(x):
    return hex(int(np.float32(x).view(np.uint32)))


reader = GGUFReader(r"G:\~dev\rawrxd\models\tinyllama.gguf")
tensor = next(t for t in reader.tensors if t.name == "blk.1.attn_q.weight")
data = bytes(tensor.data)
cols, rows = int(tensor.shape[0]), int(tensor.shape[1])
print("tensor", tensor.name, "rows", rows, "cols", cols)

norm_g = load(pick(gpu, "deep2_ATTN_NORM_1_pos1_"))
# best-match REF norm / qpre to product dumps
bestn = None
for n in os.listdir(ref):
    if n.startswith("llama_ATTN_NORM_1_pos1_") and "_n2048_" in n and n.endswith(".bin"):
        r = load(os.path.join(ref, n))
        m = float(np.max(np.abs(norm_g - r)))
        if bestn is None or m < bestn[0]:
            bestn = (m, n, r)
norm_r = bestn[2]
print("NORM", bestn[1], bestn[0])
qpre_g = load(pick(gpu, "deep2_Q_PRE_ROPE_1_pos1_"))
bestq = None
for n in os.listdir(ref):
    if n.startswith("llama_Q_PRE_ROPE_1_pos1_") and "_n2048_" in n and n.endswith(".bin"):
        r = load(os.path.join(ref, n))
        m = float(np.max(np.abs(qpre_g - r)))
        if bestq is None or m < bestq[0]:
            bestq = (m, n, r)
qpre_r = bestq[2]
print("QPRE", bestq[1], bestq[0])

qg = quantize_row_q8_K(norm_g.astype(np.float32))
qr = quantize_row_q8_K(norm_r.astype(np.float32))
bpr = cols // 256
kmask1, kmask2, kmask3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303


def unpack_scales(blk):
    utmp = list(struct.unpack_from("<III", blk, 4)) + [0]
    utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4)
    uaux = utmp[1] & kmask1
    utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4)
    utmp[2] = uaux
    utmp[0] &= kmask1
    scales = [(utmp[0] >> (8 * i)) & 0xFF for i in range(4)] + [
        (utmp[1] >> (8 * i)) & 0xFF for i in range(4)
    ]
    mins = [(utmp[2] >> (8 * i)) & 0xFF for i in range(4)] + [
        (utmp[3] >> (8 * i)) & 0xFF for i in range(4)
    ]
    return scales, mins


def row_blocks(r):
    return [
        data[(r * bpr + b) * 144 : (r * bpr + b + 1) * 144] for b in range(bpr)
    ]


def aux8_from(blk):
    aux8 = np.zeros(256, dtype=np.int32)
    a = 0
    qoff = 16
    for j in range(4):
        for l in range(32):
            aux8[a + l] = blk[qoff + l] & 15
        a += 32
        for l in range(32):
            aux8[a + l] = blk[qoff + l] >> 4
        a += 32
        qoff += 32
    return aux8


def vec_generic(blocks, qs, bsums, ds):
    sums = [0.0] * 8
    sumf = 0.0
    for bi, blk in enumerate(blocks):
        d = f16_to_f32(struct.unpack_from("<H", blk, 0)[0])
        dmin = f16_to_f32(struct.unpack_from("<H", blk, 2)[0])
        scales, mins = unpack_scales(blk)
        aux8 = aux8_from(blk)
        q8 = qs[bi * 256 : (bi + 1) * 256].astype(np.int32)
        bs = bsums[bi * 16 : (bi + 1) * 16].astype(np.int32)
        sumi = int(sum(int(bs[j]) * int(mins[j // 2]) for j in range(16)))
        aux32 = [0] * 8
        qi = ai = 0
        for j in range(8):
            scale = int(scales[j])
            for r in range(4):
                for l in range(8):
                    aux32[l] += scale * int(q8[qi + l]) * int(aux8[ai + l])
                qi += 8
                ai += 8
        xd = float(ds[bi])
        dw = np.float32(d * xd)
        for l in range(8):
            sums[l] = float(np.float32(sums[l] + float(dw) * float(aux32[l])))
        sumf = float(np.float32(sumf - np.float32(dmin * xd) * float(sumi)))
    for l in range(8):
        sumf = float(np.float32(sumf + sums[l]))
    return float(np.float32(sumf))


def vec_hybridB(blocks, qs, bsums, ds):
    """CLOSE_008 square pipe: generic aux32 lanes + AVX mins hadd + AVX hsum."""
    acc = [0.0] * 8
    acc_m = [0.0] * 4
    for bi, blk in enumerate(blocks):
        d = f16_to_f32(struct.unpack_from("<H", blk, 0)[0])
        dmin = f16_to_f32(struct.unpack_from("<H", blk, 2)[0])
        scales, mins = unpack_scales(blk)
        aux8 = aux8_from(blk)
        q8 = qs[bi * 256 : (bi + 1) * 256].astype(np.int32)
        bs = bsums[bi * 16 : (bi + 1) * 16].astype(np.int32)
        paired = [0] * 8
        for p in range(4):
            paired[p] = int(bs[2 * p] + bs[2 * p + 1])
            paired[4 + p] = int(bs[8 + 2 * p] + bs[8 + 2 * p + 1])
        xd = float(ds[bi])
        dmin_n = float(np.float32(-dmin * xd))
        for p in range(4):
            prod = int(mins[2 * p]) * paired[2 * p] + int(mins[2 * p + 1]) * paired[2 * p + 1]
            acc_m[p] = float(np.float32(acc_m[p] + dmin_n * float(prod)))
        aux32 = [0] * 8
        qi = ai = 0
        for j in range(8):
            scale = int(scales[j])
            for r in range(4):
                for l in range(8):
                    aux32[l] += scale * int(q8[qi + l]) * int(aux8[ai + l])
                qi += 8
                ai += 8
        dw = float(np.float32(d * xd))
        for l in range(8):
            acc[l] = float(np.float32(acc[l] + dw * float(aux32[l])))
    s0 = float(np.float32(float(np.float32(acc[0] + acc[4])) + float(np.float32(acc[2] + acc[6]))))
    s1 = float(np.float32(float(np.float32(acc[1] + acc[5])) + float(np.float32(acc[3] + acc[7]))))
    m = float(np.float32(float(np.float32(acc_m[0] + acc_m[2])) + float(np.float32(acc_m[1] + acc_m[3]))))
    return float(np.float32(float(np.float32(s0 + s1)) + m))


def vec_hybridC(blocks, qs, bsums, ds):
    """hybridC: generic lanes + AVX mins + generic sequential sum reduce (not hsum8)."""
    acc = [0.0] * 8
    acc_m = [0.0] * 4
    for bi, blk in enumerate(blocks):
        d = f16_to_f32(struct.unpack_from("<H", blk, 0)[0])
        dmin = f16_to_f32(struct.unpack_from("<H", blk, 2)[0])
        scales, mins = unpack_scales(blk)
        aux8 = aux8_from(blk)
        q8 = qs[bi * 256 : (bi + 1) * 256].astype(np.int32)
        bs = bsums[bi * 16 : (bi + 1) * 16].astype(np.int32)
        paired = [0] * 8
        for p in range(4):
            paired[p] = int(bs[2 * p] + bs[2 * p + 1])
            paired[4 + p] = int(bs[8 + 2 * p] + bs[8 + 2 * p + 1])
        xd = float(ds[bi])
        dmin_n = float(np.float32(-dmin * xd))
        for p in range(4):
            prod = int(mins[2 * p]) * paired[2 * p] + int(mins[2 * p + 1]) * paired[2 * p + 1]
            acc_m[p] = float(np.float32(acc_m[p] + dmin_n * float(prod)))
        aux32 = [0] * 8
        qi = ai = 0
        for j in range(8):
            scale = int(scales[j])
            for r in range(4):
                for l in range(8):
                    aux32[l] += scale * int(q8[qi + l]) * int(aux8[ai + l])
                qi += 8
                ai += 8
        dw = float(np.float32(d * xd))
        for l in range(8):
            acc[l] = float(np.float32(acc[l] + dw * float(aux32[l])))
    sumf = 0.0
    for l in range(8):
        sumf = float(np.float32(sumf + acc[l]))
    for p in range(4):
        sumf = float(np.float32(sumf + acc_m[p]))
    return float(np.float32(sumf))


def vec_avx_scalar(blocks, qs, bsums, ds):
    """AVX lane layout (maddubs groups) + AVX mins + hsum8."""
    acc = [0.0] * 8
    acc_m = [0.0] * 4
    for bi, blk in enumerate(blocks):
        d = f16_to_f32(struct.unpack_from("<H", blk, 0)[0])
        dmin = f16_to_f32(struct.unpack_from("<H", blk, 2)[0])
        scales, mins = unpack_scales(blk)
        q4 = blk[16:144]
        q8 = qs[bi * 256 : (bi + 1) * 256].astype(np.int32)
        bs = bsums[bi * 16 : (bi + 1) * 16].astype(np.int32)
        paired = [0] * 8
        for p in range(4):
            paired[p] = int(bs[2 * p] + bs[2 * p + 1])
            paired[4 + p] = int(bs[8 + 2 * p] + bs[8 + 2 * p + 1])
        xd = float(ds[bi])
        dmin_n = float(np.float32(-dmin * xd))
        for p in range(4):
            prod = int(mins[2 * p]) * paired[2 * p] + int(mins[2 * p + 1]) * paired[2 * p + 1]
            acc_m[p] = float(np.float32(acc_m[p] + dmin_n * float(prod)))
        sumi = [0] * 8
        q4o = 0
        q8o = 0
        for j in range(4):
            sl = int(scales[2 * j])
            sh = int(scales[2 * j + 1])
            for lane in range(8):
                s = 0
                for t in range(4):
                    idx = lane * 4 + t
                    s += (q4[q4o + idx] & 0xF) * int(q8[q8o + idx])
                sumi[lane] += sl * s
            q8o += 32
            for lane in range(8):
                s = 0
                for t in range(4):
                    idx = lane * 4 + t
                    s += (q4[q4o + idx] >> 4) * int(q8[q8o + idx])
                sumi[lane] += sh * s
            q8o += 32
            q4o += 32
        dw = float(np.float32(d * xd))
        for l in range(8):
            acc[l] = float(np.float32(acc[l] + dw * float(sumi[l])))
    s0 = float(np.float32(float(np.float32(acc[0] + acc[4])) + float(np.float32(acc[2] + acc[6]))))
    s1 = float(np.float32(float(np.float32(acc[1] + acc[5])) + float(np.float32(acc[3] + acc[7]))))
    m = float(np.float32(float(np.float32(acc_m[0] + acc_m[2])) + float(np.float32(acc_m[1] + acc_m[3]))))
    return float(np.float32(float(np.float32(s0 + s1)) + m))


kernels = {
    "generic": vec_generic,
    "hybridB": vec_hybridB,
    "hybridC": vec_hybridC,
    "avx_scalar": vec_avx_scalar,
}

for idx in [747, 1027, 1026]:
    blocks = row_blocks(idx)
    print(f"==== idx{idx} head{idx // 64} ====")
    print(f"  product Q_PRE {float(qpre_g[idx]):.10e} {bits(qpre_g[idx])}")
    print(f"  REF     Q_PRE {float(qpre_r[idx]):.10e} {bits(qpre_r[idx])} ulp={ulp(qpre_g[idx], qpre_r[idx])}")
    for nname, (qs, bsums, ds) in [("GPU_NORM", qg), ("REF_NORM", qr)]:
        for kname, kn in kernels.items():
            v = kn(blocks, qs, bsums, ds)
            print(
                f"  {kname:11s}({nname}) {v:.10e} {bits(v)} "
                f"ulp_spv={ulp(v, qpre_g[idx])} ulp_ref={ulp(v, qpre_r[idx])}"
            )

print("PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0")
