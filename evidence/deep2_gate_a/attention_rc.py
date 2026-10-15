#!/usr/bin/env python3
"""
DEEP2_FFN_FIRST_DIVERGENCE_001 + attention root cause.

At layer 0 position 10, q/k/v GEMV outputs are EXACTLY equal to llama.cpp
(cosine 1.000000). So any attn_out error must come from the attention
algorithm itself: RoPE, GQA head mapping, softmax, or scaling.

Reconstruct attention in Python from Deep2's exact pre-RoPE q/k/v traces,
using llama.cpp's exact algorithm, and compare against Deep2's attn_out.
"""
import os
import math
import numpy as np

D2 = r'F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone'
REF = r'F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2'

POS = 10
LAYER = 0
H = 3072
NH = 24
NKV = 8
HD = 128
THETA = 10000.0
SCALE = 1.0 / math.sqrt(HD)

def lb(p):
    with open(p, 'rb') as f:
        return np.frombuffer(f.read(), dtype='<f4').astype(np.float64)

def build_trace(pos):
    m = {}
    p = os.path.join(D2, f'd2_trace_pos{pos}.txt')
    if not os.path.exists(p):
        return m
    with open(p) as f:
        for line in f:
            if line.startswith('blk='):
                q = line.strip().split()
                m[(int(q[0].split('=')[1]), q[3].split('=')[1])] = int(q[1].split('=')[1])
    return m

def d2_tensor(pos, layer, name):
    blk = 999 if layer < 0 else layer
    tr = build_trace(pos)
    if (layer, name) not in tr:
        return None
    pc = tr[(layer, name)]
    path = os.path.join(D2, f'd2_pos{pos}_blk{blk}_pc{pc}_{name}.bin')
    return lb(path) if os.path.exists(path) else None

# ---- reference post-RoPE q/k for insight ----
def ref_tensor(pos, layer, name, stage):
    b = os.path.join(REF, f'ref_pos{pos}_layer{layer}_{name}_layer{layer}')
    c = b + ('' if stage == 0 else f'_stage{stage}') + '.bin'
    return lb(c) if os.path.exists(c) else None

# 1) Verify pre-RoPE q/k/v match reference exactly
q_raw = d2_tensor(POS, LAYER, 'q')
k_raw = d2_tensor(POS, LAYER, 'k')
v_raw = d2_tensor(POS, LAYER, 'v')
for nm, arr, st in [('q', q_raw, 1), ('k', k_raw, 1), ('v', v_raw, 1)]:
    r = ref_tensor(POS, LAYER, nm, st)
    cos = np.dot(arr, r) / (np.linalg.norm(arr) * np.linalg.norm(r))
    print(f'  pre-RoPE {nm} vs ref stage{st}: cos={cos:.10f}  (exact={cos > 0.9999999})')

# 2) Apply llama.cpp ROOPE (NeoX) to Deep2 q/k
def rope_neox(x, n_heads, pos, head_dim=HD, theta=THETA):
    out = x.copy()
    half = head_dim // 2
    for h in range(n_heads):
        b = h * head_dim
        for i in range(half):
            inv = 1.0 / (theta ** (i / half))
            ang = pos * inv
            c, s = math.cos(ang), math.sin(ang)
            x0 = out[b + i]
            x1 = out[b + i + half]
            out[b + i] = x0 * c - x1 * s
            out[b + i + half] = x0 * s + x1 * c
    return out

q_rope = rope_neox(q_raw, NH, POS)
k_rope = rope_neox(k_raw, NKV, POS)

# Compare against reference post-RoPE stage (try stages 3,4,5)
print('\n-- which reference q stage is post-RoPE? --')
for st in range(6):
    r = ref_tensor(POS, LAYER, 'q', st)
    if r is None:
        continue
    if r.shape != q_rope.shape:
        print(f'  stage{st}: shape {r.shape} != {q_rope.shape}')
        continue
    cos = np.dot(q_rope, r) / (np.linalg.norm(q_rope) * np.linalg.norm(r))
    print(f'  Deep2-RoPE vs ref stage{st}: cos={cos:.8f}')

print('\n-- same for k --')
for st in range(6):
    r = ref_tensor(POS, LAYER, 'k', st)
    if r is None:
        continue
    if r.shape != k_rope.shape:
        print(f'  stage{st}: shape {r.shape} != {k_rope.shape}')
        continue
    cos = np.dot(k_rope, r) / (np.linalg.norm(k_rope) * np.linalg.norm(r))
    print(f'  Deep2-RoPE vs ref stage{st}: cos={cos:.8f}')

# 3) Build K/V cache from Deep2 traces (pre-RoPE), apply RoPE to each cached key
print('\n-- building KV cache from Deep2 pre-RoPE traces --')
k_cache = np.zeros((NKV, POS + 1, HD))
v_cache = np.zeros((NKV, POS + 1, HD))
for p in range(POS + 1):
    kp = d2_tensor(p, LAYER, 'k')
    vp = d2_tensor(p, LAYER, 'v')
    if kp is None or vp is None:
        print(f'  pos {p}: MISSING k/v')
        continue
    k_cache[:, p, :] = kp.reshape(NKV, HD)
    v_cache[:, p, :] = vp.reshape(NKV, HD)

# 4) GQA attention, llama.cpp semantics. Apply RoPE to EVERY cached key with
#    its own position (the cache stores rotated keys).
q_heads = q_rope.reshape(NH, HD)
out_heads = np.zeros((NH, HD))
rope_cache_scaled = SCALE * SCALE  # cos^2 model, placeholder
for h in range(NH):
    kvh = h // (NH // NKV)
    scores = np.zeros(POS + 1)
    for p in range(POS + 1):
        kp = rope_neox(k_cache[kvh, p, :].copy(), 1, p)
        scores[p] = float(np.dot(q_heads[h], kp[0:HD])) / math.sqrt(HD)
    mx = scores.max()
    e = np.exp(scores - mx)
    w = e / e.sum()
    for j in range(HD):
        out_heads[h, j] = sum(w[p] * v_cache[kvh, p, j] for p in range(POS + 1))

attn_computed = out_heads.flatten()
d2_attn = d2_tensor(POS, LAYER, 'attn_out')
cos = np.dot(attn_computed, d2_attn) / (np.linalg.norm(attn_computed) * np.linalg.norm(d2_attn))
diff = attn_computed - d2_attn
print(f'\nPython-llama-attention(1/sqrt(hd) scale, RoPE per-position) vs Deep2 attn_out: cos={cos:.8f}')
print(f'  maxabs={np.max(np.abs(diff)):.6e} rmse={np.sqrt(np.mean(diff**2)):.6e}')

ref_attn = ref_tensor(POS, LAYER, 'attn_out', 0)
if ref_attn is not None and ref_attn.shape == attn_computed.shape:
    cos2 = np.dot(attn_computed, ref_attn) / (np.linalg.norm(attn_computed) * np.linalg.norm(ref_attn))
    print(f'Python-llama-attention vs REFERENCE attn_out: cos={cos2:.8f}')
    cos3 = np.dot(d2_attn, ref_attn) / (np.linalg.norm(d2_attn) * np.linalg.norm(ref_attn))
    print(f'Deep2 attn_out vs REFERENCE attn_out:        cos={cos3:.8f}')
