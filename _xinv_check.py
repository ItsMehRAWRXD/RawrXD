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
# y = Wq x' + bq -> x' = Wq^T (y - bq)  (Wq is square 5120x5120)
y = gotQ - bq
xp = np.linalg.solve(Wq, y) if False else np.linalg.lstsq(Wq, y, rcond=None)[0]
ratio = xp / x
print('ratio x_p/x: mean=%.4f std=%.4f min=%.4f max=%.4f' % (ratio.mean(), ratio.std(), ratio.min(), ratio.max()))
print('corr(x_p, x) =', float(np.corrcoef(xp[:3000], x[:3000])[0,1]))
print('first 6 ratios:', np.round(ratio[:6], 4))
