import struct, sys, os

def dump_gguf_tensors(path):
    with open(path, 'rb') as f:
        magic = f.read(4)
        version = struct.unpack('<I', f.read(4))[0]
        tc = struct.unpack('<Q', f.read(8))[0]
        mc = struct.unpack('<Q', f.read(8))[0]
        print(f'magic={magic}, version={version}, tensorCount={tc}, metaCount={mc}')
        
        # Metadata KV
        for i in range(mc):
            keyLen = struct.unpack('<Q', f.read(8))[0]
            key = f.read(keyLen).decode('utf-8')
            vtype = struct.unpack('<I', f.read(4))[0]
            
            if vtype == 0:   # UINT8
                val = struct.unpack('<B', f.read(1))[0]
            elif vtype == 1: # INT8
                val = struct.unpack('<b', f.read(1))[0]
            elif vtype == 2: # UINT16
                val = struct.unpack('<H', f.read(2))[0]
            elif vtype == 3: # INT16
                val = struct.unpack('<h', f.read(2))[0]
            elif vtype == 4: # UINT32
                val = struct.unpack('<I', f.read(4))[0]
            elif vtype == 5: # INT32
                val = struct.unpack('<i', f.read(4))[0]
            elif vtype == 6: # FLOAT32
                val = struct.unpack('<f', f.read(4))[0]
            elif vtype == 7: # BOOL
                val = struct.unpack('<?', f.read(1))[0]
            elif vtype == 8: # STRING
                sl = struct.unpack('<Q', f.read(8))[0]
                val = f.read(sl).decode('utf-8')
            elif vtype == 9: # ARRAY
                arrType = struct.unpack('<I', f.read(4))[0]
                arrLen = struct.unpack('<Q', f.read(8))[0]
                vals = []
                for _ in range(arrLen):
                    if arrType == 4:
                        vals.append(struct.unpack('<I', f.read(4))[0])
                    elif arrType == 5:
                        vals.append(struct.unpack('<i', f.read(4))[0])
                    elif arrType == 6:
                        vals.append(struct.unpack('<f', f.read(4))[0])
                    elif arrType == 8:
                        sl = struct.unpack('<Q', f.read(8))[0]
                        vals.append(f.read(sl).decode('utf-8'))
                    elif arrType == 10:
                        vals.append(struct.unpack('<Q', f.read(8))[0])
                    elif arrType == 11:
                        vals.append(struct.unpack('<q', f.read(8))[0])
                    else:
                        f.read(8)
                val = vals
            elif vtype == 10: # UINT64
                val = struct.unpack('<Q', f.read(8))[0]
            elif vtype == 11: # INT64
                val = struct.unpack('<q', f.read(8))[0]
            elif vtype == 12: # FLOAT64
                val = struct.unpack('<d', f.read(8))[0]
            
            if 'expert' in key.lower() or 'moe' in key.lower() or 'router' in key.lower() or 'layer' in key.lower():
                print(f'  META: {key} = {val}')

        # Align to 32
        pos = f.tell()
        pad = (32 - (pos % 32)) % 32
        f.read(pad)
        
        # Tensors
        print(f'\\nTENSORS:')
        for i in range(tc):
            n_dims = struct.unpack('<I', f.read(4))[0]
            dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(n_dims)]
            name_len = struct.unpack('<Q', f.read(8))[0]
            name = f.read(name_len).decode('utf-8')
            ttype = struct.unpack('<I', f.read(4))[0]
            # tensor data offset
            offset = struct.unpack('<Q', f.read(8))[0]
            # size = product(dims) * type_size
            type_sizes = {0:4, 1:2, 2:18, 3:20, 6:22, 7:24, 8:34, 9:36, 10:0, 11:0, 12:144, 13:176, 14:210}
            size = 1
            for d in dims:
                size *= d
            if ttype in type_sizes:
                size *= type_sizes[ttype]
            # align to 32
            aligned_size = ((size + 31) // 32) * 32
            
            # Only print relevant tensors
            lower = name.lower()
            if any(k in lower for k in ['expert', 'moe', 'router', 'gate', 'ffn_gate', 'ffn_up', 'ffn_down', 'ssm']):
                print(f'  [{i}] {name}: type={ttype}, dims={dims}, size={size}, offset={offset}')
            
            f.seek(aligned_size, 1)

if __name__ == '__main__':
    # Try to find Nemotron-H 30B model
    paths = [
        r'D:\rawrxd\models\_matrix_f\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf',
        r'D:\rawrxd\models\NVIDIA-Nemotron-3.5-Lightning-30B-GGUF\NVIDIA-Nemotron-3.5-Lightning-30B-Q4_K_M.gguf',
    ]
    for p in paths:
        if os.path.exists(p):
            print(f'=== Dumping: {p} ===')
            dump_gguf_tensors(p)
            print()
