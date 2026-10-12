import struct
import numpy as np
GGUF = r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
f = open(GGUF,'rb')
assert f.read(4)==b'GGUF'
ver = struct.unpack('<I', f.read(4))[0]
tc = struct.unpack('<Q', f.read(8))[0]
kc = struct.unpack('<Q', f.read(8))[0]
print('version', ver, 'tensors', tc, 'kv', kc)
def rs():
    n=struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf8','replace')
def rv(t):
    m={0:('<B',1),1:('<b',1),2:('<H',2),3:('<h',2),4:('<I',4),5:('<i',4),6:('<f',4),7:('<?',1),10:('<Q',8),11:('<q',8),12:('<d',8)}
    if t in m:
        fmt,sz=m[t]; return struct.unpack(fmt,f.read(sz))[0]
    if t==8: return rs()
    if t==9:
        et=struct.unpack('<I',f.read(4))[0]; c=struct.unpack('<Q',f.read(8))[0]
        return [rv(et) for _ in range(c)]
    raise ValueError(t)
meta={}
for _ in range(kc):
    k=rs(); t=struct.unpack('<I',f.read(4))[0]; meta[k]=rv(t)
tensors=[]
for _ in range(tc):
    nm=rs(); nd=struct.unpack('<I',f.read(4))[0]
    d=[struct.unpack('<Q',f.read(8))[0] for _ in range(nd)]
    tt=struct.unpack('<I',f.read(4))[0]
    off=struct.unpack('<Q',f.read(8))[0]
    tensors.append((nm,tt,d,off))
pos = f.tell()
print('tensor dir ends at', pos, 'file size', __import__('os').path.getsize(GGUF))
print('general.alignment =', meta.get('general.alignment'))
# candidate data start values
align = meta.get('general.alignment', 32)
print('align', align, 'aligned pos =', (pos + align - 1)//align*align)
for cand in [pos, (pos+align-1)//align*align, 3996128]:
    print('candidate data_start =', cand)
# The certified captures tell us token_embd row for a token. Use them to solve.
print()
print('first 3 tensors:')
for t in tensors[:3]:
    print('  ', t)
by = {}
for nm,tt,d,off in tensors:
    by[nm]=(tt,d,off)
for nm in ['output.weight','token_embd.weight','blk.0.attn_norm.weight','blk.0.attn_q.weight']:
    print('  %-30s %s' % (nm, by[nm]))