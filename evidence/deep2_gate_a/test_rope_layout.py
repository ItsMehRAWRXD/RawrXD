import os, math
import numpy as np

D2 = r'F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone'
REF = r'F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2'
POS, LAYER, NH, NKV, HD = 10, 0, 24, 8, 128

def lb(p):
    with open(p, 'rb') as f:
        return np.frombuffer(f.read(), dtype='<f4').astype(np.float64)

def build_trace(pos):
    m = {}
    with open(os.path.join(D2, f'd2_trace_pos{pos}.txt')) as f:
        for line in f:
            if line.startswith('blk='):
                q = line.strip().split()
                m[(int(q[0].split('=')[1]), q[3].split('=')[1])] = int(q[1].split('=')[1])
    return m

def d2t(pos, layer, name):
    tr = build_trace(pos)
    pc = tr[(layer, name)]
    return lb(os.path.join(D2, f'd2_pos{pos}_blk{layer}_pc{pc}_{name}.bin'))

def refst(name, stage):
    p = os.path.join(REF, f'ref_pos{POS}_layer{LAYER}_{name}_layer{LAYER}_stage{stage}.bin')
    return lb(p) if os.path.exists(p) else None

q_raw = d2t(POS, LAYER, 'q')
k_raw = d2t(POS, LAYER, 'k')

def rope_neox_head(h, pos, theta=10000.0):
    half = len(h) // 2
    out = h.copy()
    for i in range(half):
        inv = theta ** (-2.0 * i / (2 * half))
        ang = pos * inv
        c, s = math.cos(ang), math.sin(ang)
        x0, x1 = out[i], out[i + half]
        out[i] = x0 * c - x1 * s
        out[i + half] = x0 * s + x1 * c
    return out

# Deep2 head-major [24,128]
q_rope = np.concatenate([rope_neox_head(q_raw[h*HD:(h+1)*HD], POS) for h in range(NH)])

# Reference stages: try both layouts
for st in [4, 5]:
    r = refst('q', st)
    if r is None:
        continue
    print(f'--- stage{st} shape {r.shape} ---')
    # layout A: [NH, HD] head-major like Deep2
    cos_a = np.dot(q_rope, r) / (np.linalg.norm(q_rope) * np.linalg.norm(r))
    # layout B: [HD, NH] transposed -> (NH, HD)
    rt = r.reshape(HD, NH).T.flatten()
    cos_b = np.dot(q_rope, rt) / (np.linalg.norm(q_rope) * np.linalg.norm(rt))
    print(f'   vs [NH,HD] direct   : cos={cos_a:.8f}')
    print(f'   vs [HD,NH] transposed: cos={cos_b:.8f}')

# Now check k stages the same way with correct rotary for K's 8 heads
k_rope = np.concatenate([rope_neox_head(k_raw[h*HD:(h+1)*HD], POS) for h in range(NKV)])
for st in [4, 5]:
    r = refst('k', st)
    if r is None:
        continue
    cos_a = np.dot(k_rope, r) / (np.linalg.norm(k_rope) * np.linalg.norm(r))
    rt = r.reshape(HD, NKV).T.flatten()
    cos_b = np.dot(k_rope, rt) / (np.linalg.norm(k_rope) * np.linalg.norm(rt))
    print(f'--- k stage{st} ---')
    print(f'   vs [NKV,HD] direct   : cos={cos_a:.8f}')
    print(f'   vs [HD,NKV] transposed: cos={cos_b:.8f}')
