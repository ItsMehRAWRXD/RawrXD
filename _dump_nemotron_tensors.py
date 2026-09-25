import struct, sys

def read_string(f):
    n = struct.unpack('<Q', f.read(8))[0]
    raw = f.read(n)
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        # Some GGUF files have utf-16le metadata
        if len(raw) >= 2 and raw[1] == 0:
            return raw.decode('utf-16le')
        return raw.decode('utf-8', errors='replace')

path = sys.argv[1]
with open(path, 'rb') as f:
    magic = f.read(4)
    assert magic == b'GGUF', f"Bad magic: {magic}"
    ver = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_kv = struct.unpack('<Q', f.read(8))[0]
    print(f"GGUF v{ver}, tensors={n_tensors}, kv={n_kv}")

    # Skip metadata
    for i in range(n_kv):
        key_len = struct.unpack('<Q', f.read(8))[0]
        key_raw = f.read(key_len)
        try:
            key = key_raw.decode('utf-8')
        except UnicodeDecodeError:
            key = key_raw.decode('utf-8', errors='replace')
        vtype = struct.unpack('<I', f.read(4))[0]
        if vtype == 0: f.read(1)
        elif vtype == 1: f.read(1)
        elif vtype == 2: f.read(2)
        elif vtype == 3: f.read(2)
        elif vtype in (4,5,6): f.read(4)
        elif vtype == 7: f.read(1)
        elif vtype == 8:
            slen = struct.unpack('<Q', f.read(8))[0]
            f.read(slen)
        elif vtype == 9:
            atype = struct.unpack('<I', f.read(4))[0]
            alen = struct.unpack('<Q', f.read(8))[0]
            if atype == 8:
                for _ in range(alen):
                    slen = struct.unpack('<Q', f.read(8))[0]
                    f.read(slen)
            else:
                sz = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,10:8,11:8,12:8}.get(atype,1)
                f.read(alen*sz)
        elif vtype in (10,11,12): f.read(8)

    # Read tensor headers
    for i in range(min(n_tensors, 100)):
        name_len = struct.unpack('<Q', f.read(8))[0]
        raw = f.read(name_len)
        try:
            name = raw.decode('utf-8')
        except UnicodeDecodeError:
            name = raw.decode('utf-8', errors='replace')
        n_dims = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(n_dims)]
        ggml_type = struct.unpack('<I', f.read(4))[0]
        offset = struct.unpack('<Q', f.read(8))[0]
        print(f"{name} type={ggml_type} dims={dims}")
