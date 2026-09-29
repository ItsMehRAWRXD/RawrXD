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
def deq_row(row):
    vals = np.empty(ne0)
    for b in range(bpr):
        blk = row[b*144:(b+1)*144]
        d = float(m.F16_TAB[struct.unpack('<H', blk[0:2])[0]])
        dmin = float(m.F16_TAB[struct.unpack('<H', blk[2:4])[0]])
        s = blk[4:16].astype(np.int64)
        q = blk[16:144].astype(np.int64)
        pos = 0
        for chunk in range(4):
            isb = chunk * 2
            if isb < 4: sc, mn = s[isb] & 63, s[isb+4] & 63
            else: sc, mn = (s[isb+4] & 0xF) | ((s[isb-4] >> 6) << 4), (s[isb+4] >> 4) | ((s[isb] & 0x3F) << 4)
            slo = d * sc; mlo = dmin * mn
            seg = q[chunk*32:(chunk+1)*32]
            vals[b*256+chunk*64+0:b*256+chunk*64+32] = slo * (seg & 0xF) - mlo
            vals[b*256+chunk*64+32:b*256+chunk*64+64] = slo * (seg >> 4) - mlo
    return vals
r0 = deq_row(raw[0])
ref0 = float(np.dot(r0, x))
print('ffn_gate row0: canonical(float)=%.9f engine=%.9f  diff=%.3e' % (ref0, got[0], abs(ref0-got[0])))
r1 = deq_row(raw[1])
print('row1: canonical=%.9f engine=%.9f diff=%.3e' % (float(np.dot(r1, x)), got[1], abs(float(np.dot(r1, x))-got[1])))
