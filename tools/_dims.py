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
for name in ['blk.0.ffn_gate_exps.weight','blk.0.ffn_up_exps.weight','blk.0.ffn_down_exps.weight',
             'blk.0.ffn_gate_inp.weight','blk.0.ffn_down_shexp.weight','blk.0.ffn_gate.weight','blk.0.ffn_up.weight','blk.0.ffn_down.weight',
             'blk.0.attn_q.weight','blk.0.attn_kv_b.weight']:
    if name in tensors:
        tt, d, off = tensors[name]
        print('%-34s tt=%2d dims=%s' % (name, tt, d))
    else:
        print('%-34s ABSENT' % name)