# _l0_q_check.py — DEEP2_QWEN2_CPU_CORRECTNESS_001 diagnostic.
# Recomputes LAYER_0_Q = attn_q.weight (Q4K 5120x5120) @ EMBED(token 785)
# with the canonical llama Q4K dequant (the formula the parity gate validated)
# and compares to the engine trace's LAYER_0_Q FIRST8.
import struct, re, sys
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
            for l in range(16):
                out[idx+j+l] = ds*(q[l] & 0xF) - dm
            for l in range(16):
                out[idx+j+16+l] = ds*(q[l] >> 4) - dm
            for l in range(16):
                out[idx+j+32+l] = ds*(q[l+16] & 0xF) - dm
            for l in range(16):
                out[idx+j+48+l] = ds*(q[l+16] >> 4) - dm
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
            res = (dims, ttype, off)
            break
    f.close()
    return res

# ---- load x = EMBED row 785 (canonical dequant) ----
emb_rel = 638689280
row_bytes = 2880
f = open(PATH, 'rb')
f.seek(BASE + emb_rel + 785*row_bytes)
emb_data = f.read(row_bytes)
x = np.zeros(5120, dtype=np.float32)
deq_q4k_row(emb_data, x)
# trace EMBED first8 check
trace_first8 = [0.00507307053, 0.012816906, 0.0012011528, 0.0012011528,
                -0.0181584358, -0.00267076492, -0.00654268265, -0.0181584358]
assert np.allclose(x[:8], trace_first8, atol=1e-6), 'embed mismatch'
print('EMBED row785 verified (max diff vs trace: %.2e)'
      % np.max(np.abs(x[:8] - np.array(trace_first8))))

# ---- attn_q.weight Q4K: dims [5120(nelements per row? rows,cols)] ----
dims, ttype, rel = tensor_offset('blk.0.attn_q.weight')
rows, cols = dims[1], dims[0]   # GGUF dims reversed: shape[0]=cols
n_blocks = cols // 256
row_bytes = n_blocks * 144
print('attn_q rows', rows, 'cols', cols)

# Compare first 4 rows only (5120 rows too slow in Python for full check).
y_ref = np.zeros(5120, dtype=np.float64)
out_first8 = None
for r in range(4):
    f = open(PATH, 'rb')
    f.seek(BASE + rel + r*n_blocks*144)
    data = f.read(n_blocks*144)
    f.close()
    w = np.zeros(cols, dtype=np.float32)
    deq_q4k_row(data, w)
    y_ref[r] = np.dot(w, x)
    print('row', r, 'dot =', y_ref[r])

# ---- trace LAYER_0_Q FIRST8 ----
line = None
for l in open(TRACE, encoding='utf-8'):
    if 'CP=LAYER_0_Q ' in l:
        line = l.strip()
        break
m = re.search(r'FIRST8=([-\d.e+,]+)', line)
engine_first8 = [float(t) for t in m.group(1).split(',')]
print('engine LAYER_0_Q first8:', engine_first8)
print('ref dot rows 0..3:', [round(float(v), 6) for v in y_ref[:4]])
print('MATCH (row0 vs first8):', abs(y_ref[0] - engine_first8[0]) < 5e-4)