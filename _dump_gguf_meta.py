import struct
import sys

def read_string(f):
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf-8', errors='replace')

def read_kv_value(f, kv_type):
    if kv_type == 0:
        return struct.unpack('<I', f.read(4))[0]
    elif kv_type == 1:
        return struct.unpack('<i', f.read(4))[0]
    elif kv_type == 2:
        return struct.unpack('<f', f.read(4))[0]
    elif kv_type == 3:
        return struct.unpack('<?', f.read(1))[0]
    elif kv_type == 4:
        return read_string(f)
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
            return f'<unknown array type {arr_type} len={arr_len}>'
    elif kv_type == 6:
        return struct.unpack('<Q', f.read(8))[0]
    elif kv_type == 7:
        return struct.unpack('<q', f.read(8))[0]
    elif kv_type == 8:
        return struct.unpack('<d', f.read(8))[0]
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
        for i in range(n_meta):
            kv_type = struct.unpack('<I', f.read(4))[0]
            key = read_string(f)
            val = read_kv_value(f, kv_type)
            print(f"{key} = {val}")

if __name__ == '__main__':
    main()
