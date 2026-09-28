# _l0_q_solve.py — DEEP2_QWEN2_CPU_CORRECTNESS_001 diagnostic.
# With the FULL engine ATTNNORM vector (V) and the full engine Q vector:
#   Q_engine = attn_q(Q4K) @ V + bias  (canonical kernel math, numpy)
# Compare with the engine's full Q dump to see whether the KERNEL or the INPUT
# is at fault. Also recompute Q with x_canon for reference.
import struct, re
import numpy as np

TRACE = r'F:\~dev\_q32b_l0vec_trace.txt'
PATH = r'F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf'
BASE = 5979104

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

def load_vec(cp_name):
    vec = []
    in_vec = False
    for l in open(TRACE, encoding='utf-8'):
        if 'VEC=LAYER_0_' + cp_name in l:
            in_vec = True
            continue
        if in_vec:
            if l.startswith('STEP='):
                break
            vec.extend(float(x) for x in l.strip().split(',') if x)
            if len(vec) >= 5120:
                break
    return np.array(vec[:5120], dtype=np.float64)

V = load_vec('ATTN_NORM')
Qe = load_vec('Q')
print('V loaded', len(V), ' Q loaded', len(Qe))

dims, ttype, rel = tensor_offset('blk.0.attn_q.weight')
n_blocks = 5120 // 256
f = open(PATH, 'rb')
# bias
bias_rel = tensor_offset('blk.0.attn_q.bias')[2]
fb = open(PATH, 'rb'); fb.seek(BASE + bias_rel)
bias = np.fromfile(fb, dtype='<f4', count=5120); fb.close()

# NOTE: GGUF attn_q shape [5120(out), 5120(in)] — row r of file = output r.
# engine Q[r] = dot(W[r,:], V) + bias[r]
# Compute for the first 64 rows only (fast): each row needs full 5120 dot.
W = np.zeros((64, 5120), dtype=np.float32)
f = open(PATH, 'rb')
for r in range(64):
    f.seek(BASE + rel + r*n_blocks*144)
    data = f.read(n_blocks*144)
    deq_q4k_row(data, W[r])
f.close()
Q_ref = W.astype(np.float64) @ V + bias[:64].astype(np.float64)
diff = Qe[:64] - Q_ref
print('Q engine vs canonical(with engine V):')
print('  first8 engine:', [round(float(x), 6) for x in Qe[:8]])
print('  first8 ref   :', [round(float(x), 6) for x in Q_ref[:8]])
print('  max|diff| first64: %.6g  mean|diff|: %.6g' % (np.abs(diff).max(), np.abs(diff).mean()))