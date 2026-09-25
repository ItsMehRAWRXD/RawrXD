import struct, sys

def read_string(f):
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf-8', errors='replace')

path = sys.argv[1]
with open(path, 'rb') as f:
    magic = f.read(4)
    assert magic == b'GGUF', f"Bad magic: {magic}"
    ver = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_meta = struct.unpack('<Q', f.read(8))[0]
    print(f"GGUF v{ver}, tensors={n_tensors}, metadata={n_meta}", file=sys.stderr)
    for i in range(n_meta):
        kv_type = struct.unpack('<I', f.read(4))[0]
        key = read_string(f)
        if kv_type == 0: f.read(4)
        elif kv_type == 1: f.read(4)
        elif kv_type == 2: f.read(4)
        elif kv_type == 3: f.read(1)
        elif kv_type == 4: _ = read_string(f)
        elif kv_type == 6: f.read(8)
        elif kv_type == 7: f.read(8)
        elif kv_type == 8: f.read(8)
        else:
            arr_type = struct.unpack('<I', f.read(4))[0]
            arr_len = struct.unpack('<Q', f.read(8))[0]
            if arr_type == 4:
                for _ in range(arr_len): _ = read_string(f)
            else:
                size_map = {0:4,1:4,2:4,3:1,5:4,6:8,7:8,8:8,9:4,10:4,11:8,12:1}
                f.read(size_map.get(arr_type, 1) * arr_len)
    names = []
    for i in range(n_tensors):
        n_dims = struct.unpack('<I', f.read(4))[0]
        dims = struct.unpack(f'<{n_dims}Q', f.read(8*n_dims))
        typ = struct.unpack('<I', f.read(4))[0]
        offset = struct.unpack('<Q', f.read(8))[0]
        name = read_string(f)
        names.append(name)
    for n in names[:100]:
        print(n)
    print("...")
    for n in names:
        if 'expert' in n.lower() or 'moe' in n.lower() or 'gate' in n.lower():
            print(n)
