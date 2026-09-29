import importlib.util, numpy as np, struct
spec = importlib.util.spec_from_file_location('l4', r'F:\~dev\rawrxd\scripts\qwen2_l4_reference.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
t, ds = m.parse_header(m.GGUF)
vecs = m.parse_vecs()
x = vecs['FFN_NORM'].astype(np.float64).ravel()
got = vecs['FFN_GATE'].astype(np.float64).ravel()
name = 'blk.4.ffn_gate.weight'
dims, ttype, off = t[name]
ne0, ne1 = dims[0], dims[1]
bpr = ne0 // 256; rb = bpr * 144
f = open(m.GGUF, 'rb'); f.seek(ds + off)
raw = np.frombuffer(f.read(ne1 * rb), dtype=np.uint8).reshape(ne1, rb); f.close()
def gsm(j, s):
    if j < 4: return s[j] & 63, s[j+4] & 63
    return (s[j+4] & 0xF) | ((s[j-4] >> 6) << 4), (s[j+4] >> 4) | ((s[j] & 0x3F) << 4)
def deq_row_llama(row):
    vals = np.empty(ne0)
    for b in range(bpr):
        blk = row[b*144:(b+1)*144]
        d = float(m.F16_TAB[struct.unpack('<H', blk[0:2])[0]])
        dmin = float(m.F16_TAB[struct.unpack('<H', blk[2:4])[0]])
        q = blk[16:144]
        isb = 0
        for chunk in range(4):
            sc0, mn0 = gsm(isb, blk[4:16].astype(np.int64))
            sc1, mn1 = gsm(isb+1, blk[4:16].astype(np.int64))
            d1, m1 = d*sc0, dmin*mn0
            d2, m2 = d*sc1, dmin*mn1
            vals[b*256+chunk*64+0:b*256+chunk*64+32] = d1*(q[chunk*32:(chunk+1)*32].astype(np.int64) & 0xF) - m1
            vals[b*256+chunk*64+32:b*256+chunk*64+64] = d2*(q[chunk*32:(chunk+1)*32].astype(np.int64) >> 4) - m2
            isb += 2
    return vals
for r in range(3):
    ref = float(np.dot(deq_row_llama(raw[r]), x))
    print('LLAMA_DEQUANT row %d = %.6f   engine = %.6f   diff = %.3e' % (r, ref, got[r], abs(ref-got[r])))
