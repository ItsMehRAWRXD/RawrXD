import importlib.util, numpy as np
spec = importlib.util.spec_from_file_location('l4', r'F:\~dev\rawrxd\scripts\qwen2_l4_reference.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
t, ds = m.parse_header(m.GGUF)
vecs = m.parse_vecs()
x = vecs['ATTN_NORM'].astype(np.float64).ravel()
gotQ = vecs['Q'].astype(np.float64).ravel()
def load_f32(name):
    dims, ttype, off = t[name]
    f = open(m.GGUF, 'rb'); f.seek(ds + off)
    w = np.frombuffer(f.read(dims[0] * 4), dtype='<f4').astype(np.float64); f.close()
    return w
bq = load_f32('blk.4.attn_q.bias')
Wq = m.deq_q4k(m.GGUF, t, ds, 'blk.4.attn_q.weight')
ref = Wq @ x + bq
G = gotQ.reshape(40, 128); R = ref.reshape(40, 128)
# corr per head for head h vs all ref heads
import itertools
mismatches = []
for h in range(40):
    cors = [float(np.corrcoef(G[h], R[h2])[0,1]) for h2 in range(40)]
    best = int(np.argmax(cors))
    mismatches.append((h, best, round(cors[best],3), round(float(np.corrcoef(G[h], R[h])[0,1]),3)))
bad = [mm for mm in mismatches if mm[1] != mm[0]]
print('HEADS_WITH_PERMUTATION =', len(bad), 'of 40')
print('first 6:', mismatches[:6])
print('first bad:', bad[:4] if bad else 'NONE')
