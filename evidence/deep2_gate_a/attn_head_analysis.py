"""Analyze attn_out error distribution per head at L0 to distinguish bug vs precision."""
import os
import numpy as np

D2 = r'F:\rawrxd\evidence\deep2_gate_a\d2_gpu_milestone'
REF = r'F:\rawrxd\evidence\deep2_gate_a\ref_intermediate_v2'
POS, LAYER, NH, HD = 10, 0, 24, 128

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

d2_attn = d2t(POS, LAYER, 'attn_out')
ref_attn = lb(os.path.join(REF, f'ref_pos{POS}_layer{LAYER}_attn_out_layer{LAYER}.bin'))

diff = d2_attn - ref_attn
print(f'overall  cos={np.dot(d2_attn,ref_attn)/(np.linalg.norm(d2_attn)*np.linalg.norm(ref_attn)):.8f}')
print(f'         maxabs={np.max(np.abs(diff)):.3e}  rms={np.sqrt(np.mean(diff**2)):.3e}')
print(f'         |ref| max={np.max(np.abs(ref_attn)):.4f}  mean|x|={np.mean(np.abs(ref_attn)):.6f}')
print(f'         relative rms / mean|x| = {np.sqrt(np.mean(diff**2))/np.mean(np.abs(ref_attn)):.3e}')
print()
print('per-head analysis (head: rel_rms, maxabs, cos):')
worst = []
for h in range(NH):
    a = d2_attn[h*HD:(h+1)*HD]
    b = ref_attn[h*HD:(h+1)*HD]
    d = a - b
    rel = np.sqrt(np.mean(d**2))/max(np.mean(np.abs(b)), 1e-30)
    c = np.dot(a, b)/(np.linalg.norm(a)*np.linalg.norm(b))
    worst.append((rel, h, np.max(np.abs(d)), c))
worst.sort(reverse=True)
for rel, h, ma, c in worst[:8]:
    print(f'  head{h:2d}: rel_rms={rel:.3e}  maxabs={ma:.3e}  cos={c:.8f}')
print('  ... best heads:')
for rel, h, ma, c in worst[-3:]:
    print(f'  head{h:2d}: rel_rms={rel:.3e}  maxabs={ma:.3e}  cos={c:.8f}')

# Is the error zero-mean?
print(f'\nerror mean={np.mean(diff):+.3e}  std={np.std(diff):.3e}')
print(f'corr(err, ref) = {np.corrcoef(diff, ref_attn)[0,1]:+.4f}')
# If noise: corr ~ 0. If bias: corr near +/-1.
