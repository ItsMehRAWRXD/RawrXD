# CLOSE_007: offline host-generic Q4K×Q8K vs SPV/REF at Q_PRE idx747. PROMOTE=0
import os, struct
import numpy as np
from gguf import GGUFReader

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close006_fa")
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


reader = GGUFReader(r"G:\~dev\rawrxd\models\tinyllama.gguf")
tensor = next(t for t in reader.tensors if t.name == "blk.1.attn_q.weight")
data = bytes(tensor.data)
ne = [int(x) for x in tensor.shape]
cols, rows = ne[0], ne[1]
print("tensor", tensor.name, "ne", ne, "nbytes", len(data))

norm_g = load(pick(gpu, "deep2_ATTN_NORM_1_pos1_"))
norm_r = load(pick(ref, "llama_ATTN_NORM_1_pos1_"))
qpre_g = load(pick(gpu, "deep2_Q_PRE_ROPE_1_pos1_"))
qpre_r = load(pick(ref, "llama_Q_PRE_ROPE_1_pos1_"))
print("NORM maxAbs", float(np.abs(norm_g - norm_r).max()))
print("idx747 pre g/r", float(qpre_g[747]), float(qpre_r[747]), "ulp", ulp(qpre_g[747], qpre_r[747]))


def gemv_rows(norm, rowset):
    qs, bsums, xds = quantize_row_q8_K(norm.astype(np.float32))
    out = {}
    bpr = cols // 256
    kmask1 = 0x3F3F3F3F
    kmask2 = 0x0F0F0F0F
    kmask3 = 0x03030303
    for r in sorted(rowset):
        sums = np.zeros(8, dtype=np.float32)
        sumf = np.float32(0.0)
        for b in range(bpr):
            blk = data[(r * bpr + b) * 144 : (r * bpr + b + 1) * 144]
            d = f16_to_f32(struct.unpack_from("<H", blk, 0)[0])
            dmin = f16_to_f32(struct.unpack_from("<H", blk, 2)[0])
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
            q8 = qs[b * 256 : (b + 1) * 256].astype(np.int32)
            bs = bsums[b * 16 : (b + 1) * 16].astype(np.int32)
            sumi = int(sum(int(bs[j]) * int(mins[j // 2]) for j in range(16)))
            aux32 = np.zeros(8, dtype=np.int32)
            qi = 0
            ai = 0
            for j in range(8):
                scale = int(scales[j])
                for _ in range(4):
                    for l in range(8):
                        aux32[l] += scale * int(q8[qi + l]) * int(aux8[ai + l])
                    qi += 8
                    ai += 8
            xd = np.float32(xds[b])
            dw = np.float32(d) * xd
            for l in range(8):
                sums[l] = sums[l] + dw * np.float32(aux32[l])
            dm = np.float32(dmin) * xd
            sumf = sumf - dm * np.float32(sumi)
        for l in range(8):
            sumf = sumf + sums[l]
        out[r] = float(sumf)
    return out


targets = {747, 704}
out_gg = gemv_rows(norm_g, targets)  # generic on GPU norm
out_rg = gemv_rows(norm_r, targets)  # generic on REF norm
print(
    "generic(GPU_NORM)[747]",
    out_gg[747],
    "ulp_vs_spv",
    ulp(out_gg[747], qpre_g[747]),
    "ulp_vs_ref",
    ulp(out_gg[747], qpre_r[747]),
)
print(
    "generic(REF_NORM)[747]",
    out_rg[747],
    "ulp_vs_refQ",
    ulp(out_rg[747], qpre_r[747]),
    "ulp_vs_spv",
    ulp(out_rg[747], qpre_g[747]),
)
print("PROMOTE=0")
