import struct

p = r'F:\models\gguf\library__deepseek-coder-v2__16b.gguf'
f = open(p, 'rb')
assert f.read(4) == b'GGUF'
struct.unpack('<I', f.read(4))
tc = struct.unpack('<Q', f.read(8))[0]
kc = struct.unpack('<Q', f.read(8))[0]
print('tensor_count =', tc, ' metadata_kv_count =', kc)

def rs():
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf8', 'replace')

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
print('metadata parsed:', len(meta))

tensors = []
for _ in range(tc):
    n = rs(); nd = struct.unpack('<I', f.read(4))[0]
    d = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
    tt = struct.unpack('<I', f.read(4))[0]
    struct.unpack('<Q', f.read(8))
    tensors.append((n, d, tt))

print('tensors parsed :', len(tensors))

SUPPORTED = {0: 'F32', 2: 'Q4_0', 6: 'Q5_0', 8: 'Q8_0', 12: 'Q4_K', 14: 'Q6_K'}

bad_dtype = []
bad_blocks = []
for n, d, tt in tensors:
    if tt not in SUPPORTED:
        bad_dtype.append((n, tt, d))
        continue
    ne = 1
    for x in d:
        ne *= x
    if tt == 0:
        continue
    blk = 256 if tt in (12, 14) else 32
    if ne % blk != 0:
        bad_blocks.append((n, tt, d, ne, blk))

print()
print('unsupported dtype tensors :', len(bad_dtype))
for n, tt, d in bad_dtype[:20]:
    print('   ', n, 'type', tt, 'dims', d)
print('block-misaligned tensors :', len(bad_blocks))
for n, tt, d, ne, blk in bad_blocks[:20]:
    print('   ', n, 'type', SUPPORTED.get(tt, tt), 'dims', d, 'ne', ne, 'block', blk)

# also print metadata keys count and alignment key
print()
print('general.alignment =', meta.get('general.alignment'))
print('keys sample:', list(meta)[:5])
