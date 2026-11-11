import struct, numpy as np

p = r'F:\models\gguf\library__deepseek-coder-v2__16b.gguf'
f = open(p, 'rb')
assert f.read(4) == b'GGUF'
struct.unpack('<I', f.read(4))
tc = struct.unpack('<Q', f.read(8))[0]
kc = struct.unpack('<Q', f.read(8))[0]

def rs():
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf-8', 'replace')

def rv(t):
    m = {0:('<B',1),1:('<b',1),2:('<H',2),3:('<h',2),4:('<I',4),5:('<i',4),
         6:('<f',4),7:('<?',1),10:('<Q',8),11:('<q',8),12:('<d',8)}
    if t in m:
        fmt, sz = m[t]
        return struct.unpack(fmt, f.read(sz))[0]
    if t == 8: return rs()
    if t == 9:
        et = struct.unpack('<I', f.read(4))[0]
        c = struct.unpack('<Q', f.read(8))[0]
        return [rv(et) for _ in range(c)]
    raise ValueError()

meta = {}
for _ in range(kc):
    k = rs(); t = struct.unpack('<I', f.read(4))[0]
    meta[k] = rv(t)

tensors = {}
for _ in range(tc):
    n = rs(); nd = struct.unpack('<I', f.read(4))[0]
    d = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
    tt = struct.unpack('<I', f.read(4))[0]
    off = struct.unpack('<Q', f.read(8))[0]
    tensors[n] = (tt, d, off)

data_start = 3996128

for name in ['output_norm.weight', 'blk.0.attn_norm.weight',
             'blk.0.ffn_norm.weight', 'token_embd.weight',
             'blk.0.ffn_gate_exps.weight', 'output.weight']:
    if name not in tensors:
        print('%-32s ABSENT' % name)
        continue
    tt, d, off = tensors[name]
    f.seek(data_start + off)
    raw = f.read(32)
    print('%-32s tt=%2d off=%10d dims=%s' % (name, tt, off, d))
    print('   first32 hex: %s' % raw[:32].hex())
    if tt == 0:
        vals = np.frombuffer(raw, dtype='<f4')
        print('   as F32   : %s' % np.array2string(vals[:6], precision=6))
    elif tt in (2,):
        # Q4_0: fp16 scale then 16 bytes of nibbles
        scale = np.frombuffer(raw[:2], dtype='<f2')
        print('   as Q4_0  : scale=%s nibbles=%s' % (scale, raw[2:8].hex()))
    elif tt == 14:
        # Q6_K super-block starts with fp16 d then fp16 dmin? per ggml it is
        # ql[128] first actually. Just report raw.
        print('   as Q6_K  : raw head=%s' % raw[:8].hex())
    # non-zero?
    print('   all-zero: %s' % (raw == b'\x00' * 32))
