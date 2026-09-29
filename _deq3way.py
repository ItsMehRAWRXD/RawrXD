import importlib.util, numpy as np, struct
spec = importlib.util.spec_from_file_location('l4', r'F:\~dev\rawrxd\scripts\qwen2_l4_reference.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
t, ds = m.parse_header(m.GGUF)
vecs = m.parse_vecs()
x = vecs['FFN_NORM'].astype(np.float64).ravel()
name = 'blk.4.ffn_gate.weight'
W = m.deq_q4k(m.GGUF, t, ds, name)
# deq_q4k output for row0, block0, first 16 values:
print('deq_q4k row0 blk0 first 16:', np.round(W[0][:16], 3))
# compare deq_q4k vs llama-verbatim on the same row
dims, ttype, off = t[name]
ne0, ne1 = dims[0], dims[1]
bpr = ne0 // 256; rb = bpr * 144
f = open(m.GGUF, 'rb'); f.seek(ds + off)
raw = np.frombuffer(f.read(ne1 * rb), dtype=np.uint8).reshape(ne1, rb); f.close()
def gsm(j, s):
    if j < 4: return s[j] & 63, s[j+4] & 63
    return (s[j+4] & 0xF) | ((s[j-4] >> 6) << 4), (s[j+4] >> 4) | ((s[j] & 0x3F) << 4)
blk = raw[0][:144]
d = float(m.F16_TAB[struct.unpack('<H', blk[0:2])[0]])
dmin = float(m.F16_TAB[struct.unpack('<H', blk[2:4])[0]])
s = blk[4:16].astype(np.int64)
q = blk[16:144].astype(np.int64)
llama_vals = []
for chunk in range(4):
    isb = chunk * 2
    sc0, mn0 = gsm(isb, s); sc1, mn1 = gsm(isb+1, s)
    llama_vals.extend(list(d*sc0*(q[chunk*32:(chunk+1)*32] & 0xF) - dmin*mn0))
    llama_vals.extend(list(d*sc1*(q[chunk*32:(chunk+1)*32] >> 4) - dmin*mn1))
print('llama-verbatim blk0 first 16:', np.round(np.array(llama_vals[:16]), 3))
print('scales/mins blk0: sc0..3 =', [gsm(j, s)[0] for j in range(8)], ' mn0..3 =', [gsm(j, s)[1] for j in range(8)])
