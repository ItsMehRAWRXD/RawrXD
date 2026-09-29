import importlib.util, numpy as np, struct
spec = importlib.util.spec_from_file_location('l4', r'F:\~dev\rawrxd\scripts\qwen2_l4_reference.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
t, ds = m.parse_header(m.GGUF)
name = 'blk.4.ffn_gate.weight'
dims, ttype, off = t[name]
f = open(m.GGUF, 'rb'); f.seek(ds + off)
blk = np.frombuffer(f.read(144), dtype=np.uint8); f.close()
print('BLK0 d=', m.F16_TAB[struct.unpack('<H', blk[0:2])[0]], ' dmin=', m.F16_TAB[struct.unpack('<H', blk[2:4])[0]])
print('S12 =', [hex(b) for b in blk[4:16]])
s = blk[4:16].astype(np.int64)
def gsm(j, s):
    if j < 4: return s[j] & 63, s[j+4] & 63
    return (s[j+4] & 0xF) | ((s[j-4] >> 6) << 4), (s[j+4] >> 4) | ((s[j] & 0x3F) << 4)
for j in range(8):
    dd, mm = gsm(j, s)
    print('j=%d d=%d m=%d' % (j, dd, mm))
