import struct, sys, collections

GGUF_TYPES = {0:('B',1),1:('b',1),2:('H',2),3:('h',2),4:('I',4),5:('i',4),
              6:('f',4),7:('bool',1),8:('str',None),9:('arr',None),10:('Q',8),11:('q',8),12:('d',8)}

def read_val(f, t):
    if t == 8:
        n = struct.unpack('<Q', f.read(8))[0]
        return f.read(n).decode('utf-8', errors='replace')
    if t == 9:
        et = struct.unpack('<I', f.read(4))[0]
        n = struct.unpack('<Q', f.read(8))[0]
        out = []
        for _ in range(n):
            out.append(read_val(f, et))
        return out
    fmt, sz = GGUF_TYPES[t]
    if fmt == 'bool':
        return struct.unpack('<B', f.read(1))[0] != 0
    return struct.unpack('<' + fmt, f.read(sz))[0]

path = sys.argv[1] if len(sys.argv) > 1 else r'F:\rawrxd\models\nemotron-3.5-lightning-30b-Q4_K_M.gguf'
interest = sys.argv[2] if len(sys.argv) > 2 else 'attn'

with open(path, 'rb') as f:
    magic = f.read(4); ver = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_meta = struct.unpack('<Q', f.read(8))[0]
    meta = {}
    for _ in range(n_meta):
        kl = struct.unpack('<Q', f.read(8))[0]
        key = f.read(kl).decode('utf-8', errors='replace')
        vt = struct.unpack('<I', f.read(4))[0]
        meta[key] = read_val(f, vt)
    align = meta.get('general.alignment', 32)
    def align_up(p): return (p + align - 1) // align * align
    infos = []
    for _ in range(n_tensors):
        nl = struct.unpack('<Q', f.read(8))[0]
        name = f.read(nl).decode('utf-8', errors='replace')
        nd = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
        ttype = struct.unpack('<I', f.read(4))[0]
        off = struct.unpack('<Q', f.read(8))[0]
        infos.append((name, dims, ttype, off))

print('architecture =', meta.get('general.architecture'))
for k in sorted(meta):
    if k.startswith(meta.get('general.architecture','') + '.') and k.split('.')[-1] in (
            'block_count','embedding_length','expert_count','expert_used_count','feed_forward_length',
            'head_count','head_count_kv','key_length','value_length','context_length','vocab_size',
            'attention_head_count','attention_head_count_kv','rope_dimension_count'):
        print(' ', k, '=', meta[k])
print()
# Summaries
byrole = collections.defaultdict(set)
for name, dims, tt, off in infos:
    parts = name.split('.')
    if len(parts) >= 3 and parts[0] == 'blk':
        byrole[parts[2]].add(tuple(dims))
    else:
        byrole[name].add(tuple(dims))

print('=== distinct dim sets per role (nemotron_h) ===')
for role in sorted(byrole):
    sets = sorted(byrole[role], key=lambda s: (len(s), s))
    shown = sets if len(sets) <= 6 else sets[:6] + [('...',)]
    print(f'{role:24s} {shown}')

print()
print(f'=== tensors matching "{interest}" ===')
for name, dims, tt, off in infos:
    if interest in name:
        print(f'{name:48s} dims={dims} type={tt}')
