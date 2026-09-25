import struct, sys

def read_string(f):
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf-8', errors='replace')

def skip_value(f, kv_type):
    if kv_type == 0 or kv_type == 1 or kv_type == 9 or kv_type == 10:
        f.seek(4, 1)
    elif kv_type == 2:
        f.seek(4, 1)
    elif kv_type == 3 or kv_type == 12:
        f.seek(1, 1)
    elif kv_type == 4:
        n = struct.unpack('<Q', f.read(8))[0]
        f.seek(n, 1)
    elif kv_type == 5:
        arr_type = struct.unpack('<I', f.read(4))[0]
        arr_len = struct.unpack('<Q', f.read(8))[0]
        elem_sizes = {0:4, 1:4, 2:4, 3:1, 4:0, 6:8, 7:8, 8:8, 9:4, 10:4, 11:8, 12:1}
        if arr_type == 4:
            for _ in range(arr_len):
                slen = struct.unpack('<Q', f.read(8))[0]
                f.seek(slen, 1)
        else:
            sz = elem_sizes.get(arr_type, 4)
            f.seek(arr_len * sz, 1)
    elif kv_type == 6 or kv_type == 7 or kv_type == 11:
        f.seek(8, 1)
    elif kv_type == 8:
        f.seek(8, 1)
    else:
        raise ValueError(f"Unknown kv_type {kv_type}")

def read_value(f, kv_type):
    if kv_type == 0:
        return struct.unpack('<I', f.read(4))[0]
    elif kv_type == 1:
        return struct.unpack('<i', f.read(4))[0]
    elif kv_type == 2:
        return struct.unpack('<f', f.read(4))[0]
    elif kv_type == 3:
        return struct.unpack('<?', f.read(1))[0]
    elif kv_type == 4:
        n = struct.unpack('<Q', f.read(8))[0]
        return f.read(n).decode('utf-8', errors='replace')
    elif kv_type == 5:
        arr_type = struct.unpack('<I', f.read(4))[0]
        arr_len = struct.unpack('<Q', f.read(8))[0]
        if arr_type == 0:
            return [struct.unpack('<I', f.read(4))[0] for _ in range(arr_len)]
        elif arr_type == 1:
            return [struct.unpack('<i', f.read(4))[0] for _ in range(arr_len)]
        elif arr_type == 2:
            return [struct.unpack('<f', f.read(4))[0] for _ in range(arr_len)]
        elif arr_type == 3:
            return [struct.unpack('<?', f.read(1))[0] for _ in range(arr_len)]
        elif arr_type == 4:
            return [read_string(f) for _ in range(arr_len)]
        elif arr_type == 6:
            return [struct.unpack('<Q', f.read(8))[0] for _ in range(arr_len)]
        elif arr_type == 7:
            return [struct.unpack('<q', f.read(8))[0] for _ in range(arr_len)]
        elif arr_type == 8:
            return [struct.unpack('<d', f.read(8))[0] for _ in range(arr_len)]
        elif arr_type == 9:
            return [struct.unpack('<I', f.read(4))[0] for _ in range(arr_len)]
        elif arr_type == 10:
            return [struct.unpack('<i', f.read(4))[0] for _ in range(arr_len)]
        elif arr_type == 11:
            return [struct.unpack('<d', f.read(8))[0] for _ in range(arr_len)]
        elif arr_type == 12:
            return [struct.unpack('<?', f.read(1))[0] for _ in range(arr_len)]
        else:
            return f'<array type={arr_type} len={arr_len}>'
    elif kv_type == 6:
        return struct.unpack('<Q', f.read(8))[0]
    elif kv_type == 7:
        return struct.unpack('<q', f.read(8))[0]
    elif kv_type == 8:
        return struct.unpack('<d', f.read(8))[0]
    elif kv_type == 9:
        return struct.unpack('<I', f.read(4))[0]
    elif kv_type == 10:
        return struct.unpack('<i', f.read(4))[0]
    elif kv_type == 11:
        return struct.unpack('<d', f.read(8))[0]
    elif kv_type == 12:
        return struct.unpack('<?', f.read(1))[0]
    else:
        return f'<unknown type {kv_type}>'

def main():
    path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'
    with open(path, 'rb') as f:
        magic = f.read(4)
        assert magic == b'GGUF', f"Bad magic: {magic}"
        ver = struct.unpack('<I', f.read(4))[0]
        n_tensors = struct.unpack('<Q', f.read(8))[0]
        n_meta = struct.unpack('<Q', f.read(8))[0]
        print(f"GGUF v{ver}, tensors={n_tensors}, metadata={n_meta}", file=sys.stderr)

        # Skip tensor info
        for _ in range(n_tensors):
            name = read_string(f)
            n_dims = struct.unpack('<I', f.read(4))[0]
            for _ in range(n_dims):
                f.seek(8, 1)
            f.seek(4+8, 1)  # type + offset

        # Read metadata
        for i in range(n_meta):
            kv_type = struct.unpack('<I', f.read(4))[0]
            key = read_string(f)
            val = read_value(f, kv_type)
            if any(k in key.lower() for k in ('rope','theta','window','arch','attention')):
                print(f"{key} = {val}")

if __name__ == '__main__':
    main()
