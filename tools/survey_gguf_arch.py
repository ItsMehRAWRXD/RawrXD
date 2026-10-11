# survey_gguf_arch.py - derive the architecture taxonomy from every exposed blob.
import struct, os, json, collections, re

MAN = r'F:\models\gguf\manifest.json'
man = json.load(open(MAN))
OUT = r'F:\rawrxd\evidence\RAWRXD_GGUF_ARCH_TAXONOMY_001'
os.makedirs(OUT, exist_ok=True)

GT = {0:'F32',1:'F16',2:'Q4_0',3:'Q4_1',6:'Q5_0',7:'Q5_1',8:'Q8_0',9:'Q8_1',
      10:'Q2_K',11:'Q3_K',12:'Q4_K',13:'Q5_K',14:'Q6_K',15:'Q8_K',16:'IQ2_XXS',
      24:'IQ3_S',30:'BF16'}

def rd_str(f):
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf-8','replace')

def rv(f, t):
    m = {0:('<B',1),1:('<b',1),2:('<H',2),3:('<h',2),4:('<I',4),5:('<i',4),
         6:('<f',4),7:('<?',1),10:('<Q',8),11:('<q',8),12:('<d',8)}
    if t in m:
        fmt, sz = m[t]
        return struct.unpack(fmt, f.read(sz))[0]
    if t == 8: return rd_str(f)
    if t == 9:
        et = struct.unpack('<I', f.read(4))[0]
        cnt = struct.unpack('<Q', f.read(8))[0]
        return [rv(f, et) for _ in range(cnt)]
    raise ValueError('type %d' % t)

tax = {}
for e in man['files']:
    p = e['path']
    f = open(p, 'rb')
    assert f.read(4) == b'GGUF'
    struct.unpack('<I', f.read(4))
    tc = struct.unpack('<Q', f.read(8))[0]
    kc = struct.unpack('<Q', f.read(8))[0]
    meta = {}
    for _ in range(kc):
        k = rd_str(f); t = struct.unpack('<I', f.read(4))[0]
        meta[k] = rv(f, t)
    tensors = []
    for _ in range(tc):
        nm = rd_str(f)
        nd = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
        tt = struct.unpack('<I', f.read(4))[0]
        struct.unpack('<Q', f.read(8))[0]
        tensors.append((nm, dims, tt))
    f.close()

    arch = meta.get('general.architecture', '?')
    a = arch + '.'
    roles = collections.Counter()
    for nm, dims, tt in tensors:
        r = re.sub(r'\.\d+\.', '.N.', nm)
        roles[r] += 1
    dtypes = collections.Counter(GT.get(t[2], 'T%d' % t[2]) for t in tensors)

    if arch not in tax:
        tax[arch] = {'arch': arch, 'count': 0, 'block_counts': set(),
                     'embeddings': set(), 'fft': set(), 'ctx': set(),
                     'dtypes': collections.Counter(), 'role_schemas': [],
                     'has_nextn': False, 'metadata': {}}
    t = tax[arch]
    t['count'] += 1
    t['block_counts'].add(meta.get(a + 'block_count'))
    t['embeddings'].add(meta.get(a + 'embedding_length'))
    t['fft'].add(meta.get('general.file_type'))
    t['ctx'].add(meta.get(a + 'context_length'))
    t['dtypes'].update(dtypes)
    t['role_schemas'] = sorted(roles.keys())
    if any('nextn' in n for n, _, _ in tensors): t['has_nextn'] = True
    for mk, mv in meta.items():
        if mk.startswith(a) and any(s in mk for s in ('expert','moe','router','ssm','rope')):
            if not isinstance(mv, list):
                t['metadata'][mk[len(a):]] = mv

print('=== architecture taxonomy over %d blobs ===' % len(man['files']))
print('distinct architectures: %d\n' % len(tax))
for k in sorted(tax, key=lambda x: -tax[x]['count']):
    t = tax[k]
    print('%-16s n=%-3d blocks=%-13s emb=%-15s fft=%-9s' % (
        k, t['count'],
        str(sorted(str(x) for x in t['block_counts']))[:13],
        str(sorted(str(x) for x in t['embeddings']))[:15],
        str(sorted(str(x) for x in t['fft']))[:9]))
    print('    dtypes: %s' % ', '.join('%s=%d' % kv for kv in t['dtypes'].most_common(5)))
    if t['metadata']:
        print('    notable: %s' % ', '.join('%s=%s' % kv for kv in sorted(t['metadata'].items())[:9]))
    if t['has_nextn']: print('    has nextn (multi-token prediction)')
    print()

json.dump({k: {'arch': v['arch'], 'count': v['count'],
               'block_counts': sorted(str(x) for x in v['block_counts']),
               'embeddings': sorted(str(x) for x in v['embeddings']),
               'dtypes': dict(v['dtypes']), 'has_nextn': v['has_nextn'],
               'metadata': v['metadata'], 'role_schemas': v['role_schemas']}
          for k, v in tax.items()},
         open(os.path.join(OUT, 'taxonomy.json'), 'w'), indent=2)
print('taxonomy written to', os.path.join(OUT, 'taxonomy.json'))
