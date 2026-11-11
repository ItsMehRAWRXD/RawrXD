import struct

path = 'F:/rawrxd/nemotron-bolt.gguf'
with open(path, 'rb') as f:
    magic = f.read(4)
    version = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_meta = struct.unpack('<Q', f.read(8))[0]
    
    meta_vals = {}
    for i in range(n_meta):
        key_len = struct.unpack('<Q', f.read(8))[0]
        key = f.read(key_len).decode('utf-8', errors='replace')
        val_type = struct.unpack('<I', f.read(4))[0]
        if val_type == 8:
            str_len = struct.unpack('<Q', f.read(8))[0]
            meta_vals[key] = f.read(str_len).decode('utf-8', errors='replace')
        elif val_type == 9:
            arr_type = struct.unpack('<I', f.read(4))[0]
            arr_len = struct.unpack('<Q', f.read(8))[0]
            if arr_type == 8:
                vals = []
                for _ in range(arr_len):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    vals.append(f.read(sl).decode('utf-8', errors='replace'))
                meta_vals[key] = vals
            else:
                elem_size = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1}.get(arr_type, 4)
                raw = f.read(arr_len * elem_size)
                if arr_type == 5:
                    meta_vals[key] = list(struct.unpack(f'<{arr_len}i', raw))
                elif arr_type == 4:
                    meta_vals[key] = list(struct.unpack(f'<{arr_len}I', raw))
                elif arr_type == 6:
                    meta_vals[key] = list(struct.unpack(f'<{arr_len}f', raw))
                else:
                    meta_vals[key] = f'[ARRAY type={arr_type} len={arr_len}]'
        elif val_type == 6:
            meta_vals[key] = struct.unpack('<f', f.read(4))[0]
        elif val_type == 4:
            meta_vals[key] = struct.unpack('<I', f.read(4))[0]
        elif val_type == 5:
            meta_vals[key] = struct.unpack('<i', f.read(4))[0]
        elif val_type == 10:
            meta_vals[key] = struct.unpack('<Q', f.read(8))[0]
            f.read(8)  # already read
        elif val_type == 11:
            meta_vals[key] = struct.unpack('<q', f.read(8))[0]
        elif val_type == 12:
            meta_vals[key] = struct.unpack('<d', f.read(8))[0]
        elif val_type in (0, 1):
            meta_vals[key] = struct.unpack('<B', f.read(1))[0]
        elif val_type == 7:
            meta_vals[key] = struct.unpack('<B', f.read(1))[0] != 0
        elif val_type == 2:
            meta_vals[key] = struct.unpack('<H', f.read(2))[0]
        elif val_type == 3:
            meta_vals[key] = struct.unpack('<h', f.read(2))[0]

# Print MoE-relevant metadata
moe_keys = sorted([k for k in meta_vals.keys() if 'expert' in k.lower() or 'moe' in k.lower() or 'latent' in k.lower()])
for k in moe_keys:
    v = meta_vals[k]
    if isinstance(v, list) and len(v) > 5:
        print(f'  {k} = [{v[0]}, {v[1]}, ..., {v[-2]}, {v[-1]}] (len={len(v)})')
    else:
        print(f'  {k} = {v}')
