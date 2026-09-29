# _l0_norm_ratio_15b.py — DEEP2_QWEN2_CPU_CORRECTNESS_001 diagnostic.
# For the 1.5B model: compute canonical RMSNorm(embed785) and compare with the
# trace LAYER_0_ATTN_NORM FIRST8 to get the same "engine ratio" as the 32B had.
import struct, re
import numpy as np

PATH = r'F:\~dev\qwen2.5-coder-1.5b-base.gguf'
TRACE = r'F:\~dev\_q15b_v3_trace.txt'
TOKEN = 785   # 'The'

def f16(h):
    e = (h >> 10) & 0x1F
    frc = h & 0x3FF
    s = -1.0 if h & 0x8000 else 1.0
    if e == 0:
        return s * frc * 5.960464477539063e-08
    return s * (2.0 ** (e - 15)) * (1 + frc / 1024)

def deq_q6k_row(data, out):
    # block_q6_K: ql[128], qh[64], scales[16], d fp16; 210 bytes per 256 values.
    n_blocks = len(data) // 210
    for b in range(n_blocks):
        blk = data[b*210:(b+1)*210]
        ql = blk[0:128]
        qh = blk[128:192]
        sc = blk[192:208]
        d = f16(struct.unpack('<H', blk[208:210])[0])
        # ggml dequantize_row_q6_K exact bit layout:
        for l in range(32):
            is_ = l // 16
            base = b * 256
            # first 128 values: ql low nibbles + qh bits
            q1 = (ql[l] & 0xF) | ((qh[l >> 1] >> ((l & 1) << 2)) & 0xF0)
            out[base + l] = d * sc[is_] * (q1 - 32)
            q2 = (ql[l + 32] & 0xF) | ((qh[l + 32 >> 1] >> ((l & 1) << 2)) & 0xF0)
            out[base + 32 + l] = d * sc[is_] * (q2 - 32)

# parse header for offsets + base
f = open(PATH, 'rb')
f.read(4); struct.unpack('<I', f.read(4))
n_tensors = struct.unpack('<Q', f.read(8))[0]
n_kv = struct.unpack('<Q', f.read(8))[0]
def read_str(f):
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf-8', 'replace')
def skip_value(f, t):
    if t == 8: read_str(f)
    elif t in (0, 1, 7): f.seek(1, 1)
    elif t in (2, 3): f.seek(2, 1)
    elif t in (4, 5, 6): f.seek(4, 1)
    elif t in (10, 11, 12): f.seek(8, 1)
    elif t == 9:
        et = struct.unpack('<I', f.read(4))[0]
        n = struct.unpack('<Q', f.read(8))[0]
        for _ in range(n): skip_value(f, et)
    else: raise ValueError(t)
for _ in range(n_kv):
    k = read_str(f); t = struct.unpack('<I', f.read(4))[0]
    skip_value(f, t)
emb_rel = norm_rel = None
for _ in range(n_tensors):
    nm = read_str(f); nd = struct.unpack('<I', f.read(4))[0]
    dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
    ttype = struct.unpack('<I', f.read(4))[0]
    off = struct.unpack('<Q', f.read(8))[0]
    if nm == 'token_embd.weight': emb_rel = off
    if nm == 'blk.0.attn_norm.weight': norm_rel = off
header_end = f.tell()
f.close()
BASE = (header_end + 31) // 32 * 32

f = open(PATH, 'rb')
f.seek(BASE + emb_rel + TOKEN * 1260)
data = f.read(1260)
f.close()
emb = np.zeros(1536, dtype=np.float32)
deq_q6k_row(data, emb)

f = open(PATH, 'rb')
f.seek(BASE + norm_rel)
norm = np.fromfile(f, dtype='<f4', count=1536)
f.close()

ms = float(np.mean(emb.astype(np.float64) ** 2))
rms = np.sqrt(ms + 1e-6)
x = emb / rms * norm
print('canonical normed first8:', [float(v) for v in x[:8]])

trace8 = None
for l in open(TRACE, encoding='utf-8'):
    if 'CP=LAYER_0_ATTN_NORM ' in l:
        trace8 = [float(t) for t in re.search(r'FIRST8=([-\d.e+,]+)', l).group(1).split(',')]
        break
print('engine ATTNNORM first8 :', trace8)
if trace8:
    ratios = [trace8[i] / x[i] for i in range(8)]
    print('ratios:', [round(r, 4) for r in ratios])