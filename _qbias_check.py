import importlib.util, numpy as np, struct
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
print('ref+BIAS[:6] =', np.round(ref[:6], 4))
print('engine[:6]  =', np.round(gotQ[:6], 4))
print('corr =', float(np.corrcoef(ref[:3000], gotQ[:3000])[0,1]))
print('MAXABS =', float(np.max(np.abs(ref[:3000]-gotQ[:3000]))), 'SCALE =', float(np.max(np.abs(ref[:3000]))))
