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
name = 'blk.4.attn_q.weight'
dims, ttype, off = t[name]
ne0, ne1 = dims[0], dims[1]
bpr = ne0 // 256; rb = bpr * 144
f = open(m.GGUF, 'rb'); f.seek(ds + off)
raw = np.frombuffer(f.read(ne1 * rb), dtype=np.uint8).reshape(ne1, rb); f.close()
# per-block float contribution (canonical 32lo+32hi) for row 0
r = 0
contrib_ref = []
for b in range(bpr):
    blk = raw[r][b*144:(b+1)*144]
    d = float(m.F16_TAB[struct.unpack('<H', blk[0:2])[0]])
    dmin = float(m.F16_TAB[struct.unpack('<H', blk[2:4])[0]])
    s = blk[4:16].astype(np.int64)
    def gsm(j, s):
        if j < 4: return s[j] & 63, s[j+4] & 63
        return (s[j+4] & 0xF) | ((s[j-4] >> 6) << 4), (s[j+4] >> 4) | ((s[j] & 0x3F) << 4)
    q = blk[16:144].astype(np.int64)
    vals = np.empty(256)
    for chunk in range(4):
        isb = chunk * 2
        sc, mn = (s[isb] & 63, s[isb+4] & 63) if isb < 4 else ((s[isb+4] & 0xF) | ((s[isb-4] >> 6) << 4), (s[isb+4] >> 4) | ((s[isb] & 0x3F) << 4))
        slo = d * sc; mlo = dmin * mn
        seg = q[chunk*32:(chunk+1)*32]
        vals[chunk*64+0:chunk*64+32] = slo * (seg & 0xF) - mlo
        vals[chunk*64+32:chunk*64+64] = slo * (seg >> 4) - mlo
    contrib_ref.append(float(np.dot(vals, x[b*256:(b+1)*256])))
got = gotQ[r] - bq[r]
# cumulative: which prefix of blocks matches engine?
cum_ref = np.cumsum(contrib_ref)
print('engine total =', got)
print('ref total =', cum_ref[-1])
# find the block where cumulative diverges (binary-search-like)
for frac in (0.1, 0.25, 0.5, 0.75, 0.9, 1.0):
    i = int(frac * bpr) - 1
    print('after block', i+1, 'of', bpr, 'ref_cum = %.6f' % cum_ref[i])
