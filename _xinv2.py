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
y = gotQ - bq
xp = np.linalg.lstsq(Wq.T, y, rcond=None)[0]
ratio = xp / np.where(np.abs(x) > 1e-6, x, 1e-6)
print('TRANSPOSED solve: corr(x_p, x) =', float(np.corrcoef(xp[:3000], x[:3000])[0,1]))
print('ratio mean=%.4f std=%.4f' % (ratio.mean(), ratio.std()))
# Also: maybe the engine multiplies by attn_norm WEIGHT TWICE or norm output is x*w (elementwise) — canonical RMSNorm IS x/rms * w.
# The trace's ATTN_NORM should already be that. But if the engine's Q-GEMV input was x WITHOUT the weight (just normalized),
# then canonical Q = Wq @ (x / w) + bq? No — weight multiply happens in norm. Test: Wq @ (x/w)?
w = load_f32('blk.4.attn_norm.weight')
alt = Wq @ (x / np.where(np.abs(w) > 1e-9, w, 1.0)) + bq
print('corr(Wq@(x/w)+bq, engine) =', float(np.corrcoef(alt[:3000], gotQ[:3000])[0,1]))
