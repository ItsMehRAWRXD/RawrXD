# R88: generic vs AVX-scalar Q4KxQ8K @idx747 (host-only). PROMOTE=0
import os, struct, glob
import numpy as np

ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_attn_pre_o_1_pos1_close006_fa")
ref = os.path.join(ev, "stage_dump_ref_matched")

def pick(d, pref):
    hits = sorted(glob.glob(os.path.join(d, pref + "*_n2048_*.bin")))
    return hits[0]

def load(p):
    return np.fromfile(p, dtype=np.float32)

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
        xi = x[i * 256:(i + 1) * 256]
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
            bsums[i * 16 + j] = int(qs[i * 256 + j * 16:i * 256 + (j + 1) * 16].astype(np.int32).sum())
        ds[i] = np.float32(1.0) / iscale
    return qs, bsums, ds

def f16(h):
    return float(np.array([h], dtype=np.uint16).view(np.float16).astype(np.float32)[0])

def ulp(a, b):
    return abs(int(np.float32(a).view(np.uint32)) - int(np.float32(b).view(np.uint32)))

# Minimal GGUF: find blk.1.attn_q.weight offset via gguf if available, else raw scan
try:
    from gguf import GGUFReader
    reader = GGUFReader(r"G:\~dev\rawrxd\models\tinyllama.gguf")
    tensor = next(t for t in reader.tensors if t.name == "blk.1.attn_q.weight")
    wbytes = bytes(tensor.data)
    cols, rows = int(tensor.shape[0]), int(tensor.shape[1])
except Exception as e:
    print("GGUF_FAIL", e)
    raise SystemExit(3)

print("wq", rows, cols, len(wbytes))
norm_r = load(pick(ref, "llama_ATTN_NORM_1_pos1_"))
qpre_r = load(pick(ref, "llama_Q_PRE_ROPE_1_pos1_"))
qpre_g = load(pick(gpu, "deep2_Q_PRE_ROPE_1_pos1_"))
qs, bsums, ds = quantize_row_q8_K(norm_r[:cols])
idx = 747
bpr = cols // 256
blk_sz = 144
row = wbytes[idx * bpr * blk_sz:(idx + 1) * bpr * blk_sz]

kmask1, kmask2, kmask3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303

def vec_generic():
    sums = [0.0] * 8
    sumf = 0.0
    for bi in range(bpr):
        off = bi * blk_sz
        d = f16(row[off] | (row[off + 1] << 8))
        dmin = f16(row[off + 2] | (row[off + 3] << 8))
        xd = float(ds[bi])
        q8 = qs[bi * 256:(bi + 1) * 256].astype(np.int32)
        bs = bsums[bi * 16:(bi + 1) * 16].astype(np.int32)
        qs4 = row[off + 16:off + 144]
        aux8 = []
        for j in range(4):
            chunk = qs4[j * 32:(j + 1) * 32]
            aux8.extend([b & 0xF for b in chunk])
            aux8.extend([b >> 4 for b in chunk])
        utmp = [0, 0, 0, 0]
        utmp[0] = row[off + 4] | (row[off + 5] << 8) | (row[off + 6] << 16) | (row[off + 7] << 24)
        utmp[1] = row[off + 8] | (row[off + 9] << 8) | (row[off + 10] << 16) | (row[off + 11] << 24)
        utmp[2] = row[off + 12] | (row[off + 13] << 8) | (row[off + 14] << 16) | (row[off + 15] << 24)
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4)
        uaux = utmp[1] & kmask1
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4)
        utmp[2] = uaux
        utmp[0] &= kmask1
        scales = [(utmp[0] >> (8 * k)) & 0xFF for k in range(4)] + [(utmp[1] >> (8 * k)) & 0xFF for k in range(4)]
        mins = [(utmp[2] >> (8 * k)) & 0xFF for k in range(4)] + [(utmp[3] >> (8 * k)) & 0xFF for k in range(4)]
        sumi = 0
        for j in range(16):
            sumi += int(bs[j]) * mins[j // 2]
        aux32 = [0] * 8
        qi = ai = 0
        for j in range(8):
            scale = scales[j]
            for r in range(4):
                for l in range(8):
                    aux32[l] += scale * (int(q8[qi + l]) * aux8[ai + l])
                qi += 8
                ai += 8
        dw = np.float32(d) * np.float32(xd)
        for l in range(8):
            sums[l] = float(np.float32(sums[l]) + np.float32(dw) * np.float32(aux32[l]))
        dm = np.float32(dmin) * np.float32(xd)
        sumf = float(np.float32(sumf) - np.float32(dm) * np.float32(sumi))
    for l in range(8):
        sumf = float(np.float32(sumf) + np.float32(sums[l]))
    return sumf

def vec_avx_scalar():
    acc = [0.0] * 8
    acc_m = [0.0] * 4
    for bi in range(bpr):
        off = bi * blk_sz
        d = f16(row[off] | (row[off + 1] << 8))
        dmin_w = f16(row[off + 2] | (row[off + 3] << 8))
        xd = float(ds[bi])
        d = float(np.float32(d) * np.float32(xd))
        dmin = float(np.float32(-dmin_w) * np.float32(xd))
        q8 = qs[bi * 256:(bi + 1) * 256].astype(np.int32)
        bs = bsums[bi * 16:(bi + 1) * 16].astype(np.int32)
        qs4 = bytearray(row[off + 16:off + 144])
        utmp = [0, 0, 0, 0]
        utmp[0] = row[off + 4] | (row[off + 5] << 8) | (row[off + 6] << 16) | (row[off + 7] << 24)
        utmp[1] = row[off + 8] | (row[off + 9] << 8) | (row[off + 10] << 16) | (row[off + 11] << 24)
        utmp[2] = row[off + 12] | (row[off + 13] << 8) | (row[off + 14] << 16) | (row[off + 15] << 24)
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4)
        uaux = utmp[1] & kmask1
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4)
        utmp[2] = uaux
        utmp[0] &= kmask1
        scales = [(utmp[0] >> (8 * k)) & 0xFF for k in range(4)] + [(utmp[1] >> (8 * k)) & 0xFF for k in range(4)]
        mins = [(utmp[2] >> (8 * k)) & 0xFF for k in range(4)] + [(utmp[3] >> (8 * k)) & 0xFF for k in range(4)]
        paired = [0] * 8
        for p in range(4):
            paired[p] = int(bs[2 * p] + bs[2 * p + 1])
            paired[4 + p] = int(bs[8 + 2 * p] + bs[8 + 2 * p + 1])
        prod = [0] * 4
        for p in range(4):
            prod[p] = mins[2 * p] * paired[2 * p] + mins[2 * p + 1] * paired[2 * p + 1]
        for p in range(4):
            acc_m[p] = float(np.float32(acc_m[p]) + np.float32(dmin) * np.float32(prod[p]))
        sumi = [0] * 8
        q4 = qs4
        q8i = 0
        q4i = 0
        for j in range(4):
            sl = scales[2 * j]
            sh = scales[2 * j + 1]
            for lane in range(8):
                s = 0
                for t in range(4):
                    ix = lane * 4 + t
                    s += (q4[q4i + ix] & 0xF) * int(q8[q8i + ix])
                sumi[lane] += sl * s
            q8i += 32
            for lane in range(8):
                s = 0
                for t in range(4):
                    ix = lane * 4 + t
                    s += (q4[q4i + ix] >> 4) * int(q8[q8i + ix])
                sumi[lane] += sh * s
            q8i += 32
            q4i += 32
        for l in range(8):
            acc[l] = float(np.float32(acc[l]) + np.float32(d) * np.float32(sumi[l]))
    s = (acc[0] + acc[4]) + (acc[1] + acc[5]) + (acc[2] + acc[6]) + (acc[3] + acc[7])
    # match hsum: pairwise like AVX extract/add — use float32 stepwise
    a0 = float(np.float32(np.float32(acc[0]) + np.float32(acc[4])))
    a1 = float(np.float32(np.float32(acc[1]) + np.float32(acc[5])))
    a2 = float(np.float32(np.float32(acc[2]) + np.float32(acc[6])))
    a3 = float(np.float32(np.float32(acc[3]) + np.float32(acc[7])))
    s = float(np.float32(np.float32(np.float32(a0) + np.float32(a1)) + np.float32(np.float32(a2) + np.float32(a3))))
    m = float(np.float32(np.float32(acc_m[0]) + np.float32(acc_m[2])))
    m = float(np.float32(m) + np.float32(np.float32(acc_m[1]) + np.float32(acc_m[3])))
    return float(np.float32(s) + np.float32(m))

g = vec_generic()
a = vec_avx_scalar()
print("idx747 REF/llama %.10e" % float(qpre_r[idx]))
print("idx747 SPV/gpu  %.10e" % float(qpre_g[idx]))
print("generic(REF_NORM) %.10e ulp_ref=%u ulp_spv=%u" % (g, ulp(g, qpre_r[idx]), ulp(g, qpre_g[idx])))
print("avx_sc(REF_NORM)  %.10e ulp_ref=%u ulp_spv=%u" % (a, ulp(a, qpre_r[idx]), ulp(a, qpre_g[idx])))
print("generic_vs_avx ulp=%u" % ulp(g, a))
print("PROMOTE=0")
