import struct
path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'

def skip_value(f, typ):
    ts={0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,8:8,9:0,10:8,11:8,12:8}
    if typ == 8:
        slen = struct.unpack('<Q', f.read(8))[0]
        f.seek(slen, 1)
    elif typ == 9:
        arr_typ = struct.unpack('<I', f.read(4))[0]
        arr_len = struct.unpack('<Q', f.read(8))[0]
        for _ in range(arr_len):
            skip_value(f, arr_typ)
    elif typ in ts:
        f.seek(ts[typ], 1)
    else:
        raise RuntimeError(f'unknown type {typ}')

with open(path, 'rb') as f:
    magic = f.read(4)
    version = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_meta = struct.unpack('<Q', f.read(8))[0]
    print('version', version, 'tensors', n_tensors, 'meta', n_meta)
    for i in range(n_meta):
        key_len = struct.unpack('<Q', f.read(8))[0]
        f.seek(key_len, 1)
        typ = struct.unpack('<I', f.read(4))[0]
        skip_value(f, typ)
    pos = f.tell()
    pad = (32 - pos % 32) % 32
    f.seek(pad, 1)
    print('pos after meta align', f.tell())
    # read first 5 tensor infos
    for i in range(5):
        nl = struct.unpack('<Q', f.read(8))[0]
        name = f.read(nl).decode('utf-8', errors='replace')
        nd = struct.unpack('<I', f.read(4))[0]
        shape = []
        for _ in range(nd):
            shape.append(struct.unpack('<Q', f.read(8))[0])
        typ = struct.unpack('<I', f.read(4))[0]
        off = struct.unpack('<Q', f.read(8))[0]
        print(name, shape, 'type', typ, 'off', off)
