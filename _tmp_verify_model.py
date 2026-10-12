import struct, os

TSIZE = {0:4, 1:2, 2:18, 3:20, 6:22, 7:24, 8:34, 9:36, 10:10, 11:18, 12:18, 13:22, 14:32, 15:36, 30:2}
GGUF_TYPES = {0:('B',1), 1:('b',1), 2:('H',2), 3:('h',2), 4:('I',4), 5:('i',4),
              6:('f',4), 7:('bool',1), 8:('str',None), 9:('arr',None), 10:('Q',8), 11:('q',8), 12:('d',8)}


def read_val(f, t):
    if t == 8:
        n = struct.unpack('<Q', f.read(8))[0]
        return f.read(n).decode('utf-8', errors='replace')
    if t == 9:
        et = struct.unpack('<I', f.read(4))[0]
        n = struct.unpack('<Q', f.read(8))[0]
        return [read_val(f, et) for _ in range(n)]
    fmt, sz = GGUF_TYPES[t]
    if fmt == 'bool':
        return struct.unpack('<B', f.read(1))[0] != 0
    return struct.unpack('<' + fmt, f.read(sz))[0]


path = r'F:\rawrxd\models\nemotron-3.5-lightning-30b-Q4_K_M.gguf'
fsize = os.path.getsize(path)
print('file size = {:,}'.format(fsize))

f = open(path, 'rb')
try:
    f.read(4)
    ver = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_meta = struct.unpack('<Q', f.read(8))[0]
    for _ in range(n_meta):
        kl = struct.unpack('<Q', f.read(8))[0]
        f.read(kl)
        read_val(f, struct.unpack('<I', f.read(4))[0])
    infos = []
    for _ in range(n_tensors):
        nl = struct.unpack('<Q', f.read(8))[0]
        name = f.read(nl).decode('utf-8', errors='replace')
        nd = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
        tt = struct.unpack('<I', f.read(4))[0]
        off = struct.unpack('<Q', f.read(8))[0]
        infos.append((name, dims, tt, off))
    data_start = f.tell()
    data_start = (data_start + 31) // 32 * 32   # general.alignment default 32
    print('data_start = {:,} (aligned)'.format(data_start))

    total = 0
    max_end = 0
    over = []
    for name, dims, tt, off in infos:
        ne = 1
        for d in dims:
            ne *= d
        if tt in (0, 1, 30):
            nbytes = ne * (4 if tt == 0 else 2)
        else:
            ts = TSIZE.get(tt)
            nbytes = (ne // 32) * ts if ts else 0
        total += nbytes
        end = data_start + off + nbytes
        if end > max_end:
            max_end = end
        if end > fsize:
            over.append((name, tt, off, nbytes, end))
    print('sum tensor bytes = {:,} ({:.3f} GB)'.format(total, total / 1e9))
    print('max end = {:,}  overrun = {:,}'.format(max_end, max_end - fsize))
    print('tensors past EOF: {}'.format(len(over)))
    for o in over[:6]:
        print('  OVER:', o[0], 'type', o[1], 'off', o[2], 'bytes', o[3], 'end', o[4])

    def rd(nm):
        for x in infos:
            if x[0] == nm:
                return x
        return None

    for probe in ['blk.0.attn_norm.weight', 'blk.0.ssm_d', 'blk.0.ssm_dt.bias', 'blk.0.ssm_a',
                  'output_norm.weight', 'blk.0.ssm_norm.weight', 'blk.21.ssm_out.weight']:
        r = rd(probe)
        if not r:
            print(probe, 'MISSING')
            continue
        _, dims, tt, off = r
        f.seek(data_start + off)
        if tt == 0:
            ne = 1
            for d in dims:
                ne *= d
            n = min(ne, 6)
            v = struct.unpack('<' + 'f' * n, f.read(4 * n))
            v2 = ()
            if ne > 12:
                f.seek(data_start + off + (ne // 2) * 4)
                v2 = struct.unpack('<' + 'f' * 6, f.read(24))
            print('{}: dims={} F32 first={} mid={}'.format(probe, dims, v, v2))
        else:
            print('{}: dims={} type={}'.format(probe, dims, tt))
finally:
    f.close()
