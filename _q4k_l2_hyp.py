# _q4k_l2_hyp.py — RMSNORM_PARITY_001 pre-work / Q4K dequant hypothesis test.
# The 1.9643x "ATTNNORM ratio" hypothesis test: the engine EMBED trace reports
# L2=1.90489758 for token_embd row 785. Compute the row under:
#   H1: one scale pair per 64-chunk, 16lo/16hi sub-block order (my old Python)
#   H2: llama dequantize_row_q4_K — 32lo (pair is) + 32hi (pair is+1), is += 2
# and compare L2/MIN/MAX against the trace stats.
import struct
import numpy as np

PATH = r'F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf'
BASE = 5979104
EMB_REL = 638689280
ROW = 785
ROW_BYTES = 2880
TRACE_L2 = 1.90489758
TRACE_MIN = -0.530639648
TRACE_MAX = 0.388207912
TRACE_FIRST8 = [0.00507307053, 0.012816906, 0.0012011528, 0.0012011528,
                -0.0181584358, -0.00267076492, -0.00654268265, -0.0181584358]

def f16(h):
    e = (h >> 10) & 0x1F
    frc = h & 0x3FF
    s = -1.0 if h & 0x8000 else 1.0
    if e == 0:
        return s * frc * 5.960464477539063e-08
    return s * (2.0 ** (e - 15)) * (1 + frc / 1024)

def scale_min(j, s):
    # llama get_scale_min_k4 (6-bit fields, 12 bytes = 8 pairs)
    if j < 4:
        return s[j] & 63, s[j + 4] & 63
    return (s[j + 4] & 0xF) | ((s[j - 4] >> 6) << 4), \
           (s[j + 4] >> 4) | ((s[j] >> 6) << 4)

def deq(data, mode):
    out = np.zeros(len(data) // 144 * 256, dtype=np.float64)
    for b in range(len(data) // 144):
        blk = data[b*144:(b+1)*144]
        d = f16(struct.unpack('<H', blk[0:2])[0])
        dmin = f16(struct.unpack('<H', blk[2:4])[0])
        s = blk[4:16]
        q = blk[16:]
        idx = b * 256
        if mode == 'H1':   # one pair per 64-chunk, 16lo/16hi sub-blocks
            for j in range(0, 256, 64):
                is_ = j // 32
                sc, mn = scale_min(is_, s)
                ds = d * sc; dm = dmin * mn
                for l in range(16): out[idx+j+l]      = ds*(q[l] & 0xF) - dm
                for l in range(16): out[idx+j+16+l]   = ds*(q[l] >> 4) - dm
                for l in range(16): out[idx+j+32+l]   = ds*(q[l+16] & 0xF) - dm
                for l in range(16): out[idx+j+48+l]   = ds*(q[l+16] >> 4) - dm
                q = q[32:]
        else:  # H2: llama — 32lo (pair is) + 32hi (pair is+1), is += 2
            is_ = 0
            for j in range(0, 256, 64):
                sc, mn = scale_min(is_, s)
                d1 = d * sc; m1 = dmin * mn
                sc2, mn2 = scale_min(is_ + 1, s)
                d2 = d * sc2; m2 = dmin * mn2
                for l in range(32): out[idx+j+l]    = d1*(q[l] & 0xF) - m1
                for l in range(32): out[idx+j+32+l] = d2*(q[l] >> 4) - m2
                q = q[32:]
                is_ += 2
    return out

f = open(PATH, 'rb')
f.seek(BASE + EMB_REL + ROW * ROW_BYTES)
data = f.read(ROW_BYTES)
f.close()

for mode in ('H1', 'H2'):
    v = deq(data, mode)
    l2 = float(np.sqrt((v ** 2).sum()))
    first8_ok = max(abs(v[i] - TRACE_FIRST8[i]) for i in range(8)) < 1e-6
    print('%s: L2=%.6f (trace %.6f)  MIN=%.6f (trace %.6f)  MAX=%.6f (trace %.6f)  first8_match=%s'
          % (mode, l2, TRACE_L2, v.min(), TRACE_MIN, v.max(), TRACE_MAX, first8_ok))
# expected: H1 L2 ~3.74 (wrong tail), H2 L2 ~1.9049 == trace