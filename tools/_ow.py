import struct
p = r"F:\models\gguf\library__deepseek-coder-v2__16b.gguf"
f = open(p, 'rb'); assert f.read(4)==b'GGUF'
struct.unpack('<I', f.read(4))
tc = struct.unpack('<Q', f.read(8))[0]
kc = struct.unpack('<Q', f.read(8))[0]
def rs():
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf8','replace')
def rv(t):
    m = {0:('<B',1),1:('<b',1),2:('<H',2),3:('<h',2),4:('<I',4),5:('<i',4),6:('<f',4),7:('<?',1),10:('<Q',8),11:('<q',8),12:('<d',8)}
    if t in m:
        fmt, sz = m[t]
        return struct.unpack(fmt, f.read(sz))[0]
    if t == 8: return rs()
    if t == 9:
        et = struct.unpack('<I', f.read(4))[0]
        c = struct.unpack('<Q', f.read(8))[0]
        return [rv(et) for _ in range(c)]
    raise ValueError()
for _ in range(kc):
    rs(); t = struct.unpack('<I', f.read(4))[0]; rv(t)
tensors = {}
for _ in range(tc):
    n = rs(); nd = struct.unpack('<I', f.read(4))[0]
    d = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
    tt = struct.unpack('<I', f.read(4))[0]
    off = struct.unpack('<Q', f.read(8))[0]
    tensors[n] = (tt, d, off)
for name in ['output.weight', 'token_embd.weight', 'output_norm.weight']:
    tt, d, off = tensors[name]
    f.seek(3996128+off)
    raw = f.read(64)
    print('%-24s tt=%2d dims=%s off=%d bytes=%d' % (name, tt, d, off, (d[0] if len(d)>1 else 0)))