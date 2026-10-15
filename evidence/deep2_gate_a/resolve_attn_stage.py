"""Resolve which reference stage corresponds to Deep2's attn_out vs attn_proj."""
import os, glob
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

d2_out = d2t(POS, LAYER, 'attn_out')      # pre-O weighted sum
d2_proj = d2t(POS, LAYER, 'attn_proj')    # post-O projection

print('Deep2 attn_out  (pre-O)  shape', d2_out.shape)
print('Deep2 attn_proj (post-O) shape', d2_proj.shape)
print()

for f in sorted(glob.glob(os.path.join(REF, f'ref_pos{POS}_layer{LAYER}_attn_out*'))):
    r = lb(f)
    tag = os.path.basename(f).replace(f'ref_pos{POS}_layer{LAYER}_attn_out_layer{LAYER}', '') or 'stage0'
    if r.shape != d2_out.shape:
        print(f'  ref {tag:10s}: shape {r.shape} != {d2_out.shape} (skip)')
        continue
    c1 = np.dot(d2_out, r)/(np.linalg.norm(d2_out)*np.linalg.norm(r))
    c2 = np.dot(d2_proj, r)/(np.linalg.norm(d2_proj)*np.linalg.norm(r))
    print(f'  ref {tag:10s}:  pre-O cos={c1:.10f}   post-O cos={c2:.10f}')

# also resid1
r = d2t(POS, LAYER, 'resid1')
print('\nDeep2 resid1 (post attn+resid) shape', r.shape)
for f in sorted(glob.glob(os.path.join(REF, f'ref_pos{POS}_layer{LAYER}_resid*'))):
    rr = lb(f)
    tag = os.path.basename(f).replace(f'ref_pos{POS}_layer{LAYER}_resid_layer{LAYER}', '') or 'stage0'
    if rr.shape != r.shape:
        continue
    c = np.dot(r, rr)/(np.linalg.norm(r)*np.linalg.norm(rr))
    print(f'  ref {tag:10s}: resid1 cos={c:.10f}')
