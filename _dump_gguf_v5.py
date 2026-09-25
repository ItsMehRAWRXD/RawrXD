import struct, sys

def read_string(f):
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf-8', errors='replace')

def skip_value(f, vtype):
    # Types per llama.cpp GGUF v3 spec:
    # 0:uint8(1), 1:int8(1), 2:uint16(2), 3:int16(2), 4:uint32(4), 5:int32(4)
    # 6:float32(4), 7:bool(1), 8:string(Q+bytes), 9:array, 10:uint64(8), 11:int64(8), 12:float64(8)
    if vtype in (0,1,7):
        f.seek(1, 1)
    elif vtype in (2,3):
        f.seek(2, 1)
    elif vtype in (4,5,6):
        f.seek(4, 1)
    elif vtype == 8:
        n = struct.unpack('<Q', f.read(8))[0]
        f.seek(n, 1)
    elif vtype == 9:
        atype = struct.unpack('<I', f.read(4))[0]
        alen = struct.unpack('<Q', f.read(8))[0]
        if atype == 8:
            for _ in range(alen):
                slen = struct.unpack('<Q', f.read(8))[0]
                f.seek(slen, 1)
        else:
            elem_sz = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,10:8,11:8,12:8}.get(atype, 1)
            f.seek(alen * elem_sz, 1)
    elif vtype in (10,11,12):
        f.seek(8, 1)
    else:
        raise ValueError(f"Unknown vtype {vtype}")

def read_value(f, vtype):
    if vtype == 0:
        return struct.unpack('<B', f.read(1))[0]
    elif vtype == 1:
        return struct.unpack('<b', f.read(1))[0]
    elif vtype == 2:
        return struct.unpack('<H', f.read(2))[0]
    elif vtype == 3:
        return struct.unpack('<h', f.read(2))[0]
    elif vtype == 4:
        return struct.unpack('<I', f.read(4))[0]
    elif vtype == 5:
        return struct.unpack('<i', f.read(4))[0]
    elif vtype == 6:
        return struct.unpack('<f', f.read(4))[0]
    elif vtype == 7:
        return struct.unpack('<?', f.read(1))[0]
    elif vtype == 8:
        return read_string(f)
    elif vtype == 9:
        atype = struct.unpack('<I', f.read(4))[0]
        alen = struct.unpack('<Q', f.read(8))[0]
        if atype == 8:
            return [read_string(f) for _ in range(alen)]
        elif atype == 4:
            return [struct.unpack('<I', f.read(4))[0] for _ in range(alen)]
        elif atype == 5:
            return [struct.unpack('<i', f.read(4))[0] for _ in range(alen)]
        elif atype == 6:
            return [struct.unpack('<f', f.read(4))[0] for _ in range(alen)]
        elif atype == 10:
            return [struct.unpack('<Q', f.read(8))[0] for _ in range(alen)]
        elif atype == 11:
            return [struct.unpack('<q', f.read(8))[0] for _ in range(alen)]
        elif atype == 12:
            return [struct.unpack('<d', f.read(8))[0] for _ in range(alen)]
        else:
            return f'<array type={atype} len={alen}>'
    elif vtype == 10:
        return struct.unpack('<Q', f.read(8))[0]
    elif vtype == 11:
        return struct.unpack('<q', f.read(8))[0]
    elif vtype == 12:
        return struct.unpack('<d', f.read(8))[0]
    else:
        return f'<unknown type {vtype}>'

def main():
    path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'
    with open(path, 'rb') as f:
        magic = f.read(4)
        assert magic == b'GGUF', f"Bad magic: {magic}"
        ver = struct.unpack('<I', f.read(4))[0]
        n_tensors = struct.unpack('<Q', f.read(8))[0]
        n_kv = struct.unpack('<Q', f.read(8))[0]
        print(f"GGUF v{ver}, tensors={n_tensors}, kv={n_kv}", file=sys.stderr)

        # Read metadata
        for i in range(n_kv):
            key_len = struct.unpack('<Q', f.read(8))[0]
            key = f.read(key_len).decode('utf-8', errors='replace')
            vtype = struct.unpack('<I', f.read(4))[0]
            val = read_value(f, vtype)
            if any(k in key.lower() for k in ('rope','theta','window','arch','attention','head_count','key_length','layer_norm','qk','kv_per_head','freq_base','sliding','norm','context_length','embedding_length','block_count','vocab_size')):
                print(f"{key} = {val}")

        print(f"Metadata ends at offset {f.tell()}", file=sys.stderr)

if __name__ == '__main__':
    main()
