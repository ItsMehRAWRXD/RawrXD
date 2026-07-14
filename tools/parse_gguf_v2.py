import struct
import os

filepath = r'D:\test_model.gguf'
size = os.path.getsize(filepath)
print(f'File size: {size} bytes', flush=True)

with open(filepath, 'rb') as f:
    # Read header
    f.read(4)  # magic
    f.read(4)  # version
    tensor_count = struct.unpack('<Q', f.read(8))[0]
    metadata_count = struct.unpack('<Q', f.read(8))[0]
    print(f'Tensors: {tensor_count}, Metadata: {metadata_count}', flush=True)
    
    # Read all metadata
    for i in range(metadata_count):
        key_len = struct.unpack('<Q', f.read(8))[0]
        key = f.read(key_len)
        value_type = struct.unpack('<I', f.read(4))[0]
        
        if value_type == 8:  # STRING
            str_len = struct.unpack('<Q', f.read(8))[0]
            f.read(str_len)
        elif value_type == 4:  # UINT32
            f.read(4)
        elif value_type == 5:  # INT32
            f.read(4)
        elif value_type == 7:  # UINT64
            f.read(8)
        elif value_type == 6:  # FLOAT32
            f.read(4)
        elif value_type == 10:  # BOOL
            f.read(1)
        elif value_type == 12:  # ARRAY
            arr_type = struct.unpack('<I', f.read(4))[0]
            arr_len = struct.unpack('<Q', f.read(8))[0]
            for j in range(arr_len):
                if arr_type == 4:  # UINT32
                    f.read(4)
                elif arr_type == 8:  # STRING
                    s_len = struct.unpack('<Q', f.read(8))[0]
                    f.read(s_len)
    
    print(f'Position after metadata: {f.tell()}', flush=True)
    
    # Parse tensor info
    tensors = []
    for i in range(tensor_count):
        name_len = struct.unpack('<Q', f.read(8))[0]
        name = f.read(name_len).decode('utf-8', errors='replace')
        n_dims = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(n_dims)]
        dtype = struct.unpack('<I', f.read(4))[0]
        offset = struct.unpack('<Q', f.read(8))[0]
        
        tensors.append({
            'name': name,
            'dims': dims,
            'dtype': dtype,
            'offset': offset
        })
    
    print(f'Parsed {len(tensors)} tensors', flush=True)
    
    # Print first 10
    for t in tensors[:10]:
        print(f"{t['name']}: shape={t['dims']}, dtype={t['dtype']}, offset={t['offset']}", flush=True)
    
    # Write binary index
    data_offset = (f.tell() + 31) & ~31
    print(f'Data offset: {data_offset}', flush=True)
    
    with open(r'D:\rawrxd\models\test_model.index.bin', 'wb') as out:
        # Header
        out.write(struct.pack('<I', 3))  # version
        out.write(struct.pack('<Q', tensor_count))
        out.write(struct.pack('<Q', data_offset))
        
        # Tensors
        for t in tensors:
            name_bytes = t['name'].encode('utf-8')
            out.write(struct.pack('<Q', len(name_bytes)))
            out.write(name_bytes)
            out.write(struct.pack('<I', len(t['dims'])))
            for d in t['dims']:
                out.write(struct.pack('<Q', d))
            out.write(struct.pack('<I', t['dtype']))
            out.write(struct.pack('<Q', t['offset']))
    
    print('Index written to D:\\rawrxd\\models\\test_model.index.bin', flush=True)
