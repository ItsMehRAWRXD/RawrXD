# _l0_q_check2.py — DEEP2_QWEN2_CPU_CORRECTNESS_001 diagnostic (full L0 chain).
# x = rmsnorm(embed785, attn_norm, eps=1e-6); Q = attn_q(Q4K) @ x + bias.
# Compare to trace LAYER_0_ATTN_NORM + LAYER_0_Q FIRST8.
import struct, re
import numpy as np

PATH = r'F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf'
BASE = 5979104
TRACE = r'F:\~dev\_qwen2_32b_fixed_trace.txt'

def f16(h):
    e = (h >> 10) & 0x1F
    frc = h & 0x3FF
    s = -1.0 if h & 0x8000 else 1.0
    if e == 0:
        return s * frc * 5.960464477539063e-08
    return s * (2.0 ** (e - 15)) * (1 + frc / 1024)

def deq_q4k_row(data, out):
    n_blocks = len(data) // 144
    idx = 0
    for b in range(n_blocks):
        blk = data[b*144:(b+1)*144]
        d = f16(struct.unpack('<H', blk[0:2])[0])
        dmin = f16(struct.unpack('<H', blk[2:4])[0])
        s = blk[4:16]
        sc = [0]*8; mn = [0]*8
        for j in range(4):
            sc[j] = s[j] & 63; mn[j] = s[j+4] & 63
        for j in range(4, 8):
            sc[j] = (s[j+4] & 0xF) | ((s[j-4] >> 6) << 4)
            mn[j] = (s[j+4] >> 4) | ((s[j] >> 6) << 4)
        q = blk[16:]
        for j in range(0, 256, 64):
            is_ = j // 32
            ds = d * sc[is_]; dm = dmin * mn[is_]
            for l in range(16): out[idx+j+l] = ds*(q[l] & 0xF) - dm
            for l in range(16): out[idx+j+16+l] = ds*(q[l] >> 4) - dm
            for l in range(16): out[idx+j+32+l] = ds*(q[l+16] & 0xF) - dm
            for l in range(16): out[idx+j+48+l] = ds*(q[l+16] >> 4) - dm
            q = q[32:]
        idx += 256

def tensor_offset(name):
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
    res = None
    for _ in range(n_tensors):
        nm = read_str(f); nd = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
        ttype = struct.unpack('<I', f.read(4))[0]
        off = struct.unpack('<Q', f.read(8))[0]
        if nm == name:
            res = (dims, ttype, off); break
    f.close()
    return res

def read_f32(name, count):
    dims, ttype, rel = tensor_offset(name)
    f = open(PATH, 'rb')
    f.seek(BASE + rel)
    a = np.fromfile(f, dtype='<f4', count=count)
    f.close()
    return a

# ---- EMBED ----
emb_rel = 638689280
f = open(PATH, 'rb'); f.seek(BASE + emb_rel + 785*2880)
emb_data = f.read(2880); f.close()
emb = np.zeros(5120, dtype=np.float32)
deq_q4k_row(emb_data, emb)

# ---- attn_norm.weight ----
norm = read_f32('blk.0.attn_norm.weight', 5120)

# ---- RMSNorm ----
rms = np.sqrt(np.mean(emb.astype(np.float64) ** 2) + 1e-6)
x = emb / rms * norm
print('normed x first8:', [float(v) for v in x[:8]])

# ---- trace LAYER_0_ATTN_NORM + LAYER_0_Q FIRST8 ----
norm8 = q8 = None
for l in open(TRACE, encoding='utf-8'):
    if 'CP=LAYER_0_ATTN_NORM ' in l and norm8 is None:
        norm8 = [float(t) for t in re.search(r'FIRST8=([-\d.e+,]+)', l).group(1).split(',')]
    if 'CP=LAYER_0_Q ' in l and q8 is None:
        q8 = [float(t) for t in re.search(r'FIRST8=([-\d.e+,]+)', l).group(1).split(',')]
print('trace ATTNNORM first8:', norm8)
print('trace Q first8      :', q8)

# ---- attn_q rows 0..7 dequant + dot + bias ----
dims, ttype, rel = tensor_offset('blk.0.attn_q.weight')
n_blocks = 5120 // 256
f = open(PATH, 'rb')
bias_rel = tensor_offset('blk.0.attn_q.bias')[2]
fb = open(PATH, 'rb'); fb.seek(BASE + bias_rel)
bias = np.fromfile(fb, dtype='<f4', count=5120); fb.close()
for r in range(4):
    f.seek(BASE + rel + r*n_blocks*144)
    data = f.read(n_blocks*144)
    w = np.zeros(5120, dtype=np.float32)
    deq_q4k_row(data, w)
    qv = float(np.dot(w, x) + bias[r])
    print('row', r, 'ref Q=', round(qv, 6), 'engine Q=', q8[r],
          'diff=', round(qv - q8[r], 6))
f.close()