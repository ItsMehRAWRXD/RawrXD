import struct
with open('src/validation/test_model.gguf', 'rb') as f:
    f.seek(466)
    print('=== First Tensor ===')
    name_len = struct.unpack('<Q', f.read(8))[0]
    print(f'Name length: {name_len}')
    name = f.read(name_len).decode('utf-8', errors='replace')
    print(f'Name: "{name}"')
    n_dims = struct.unpack('<I', f.read(4))[0]
    print(f'n_dims: {n_dims}')
    for d in range(n_dims):
        dim = struct.unpack('<Q', f.read(8))[0]
        print(f'  dim[{d}]: {dim}')
    ttype = struct.unpack('<I', f.read(4))[0]
    print(f'type: {ttype}')
    offset = struct.unpack('<Q', f.read(8))[0]
    print(f'offset: {offset}')
    print(f'Position after first tensor: {f.tell()}')
    
    print('\n=== Second Tensor ===')
    name_len = struct.unpack('<Q', f.read(8))[0]
    print(f'Name length: {name_len}')
    name = f.read(name_len).decode('utf-8', errors='replace')
    print(f'Name: "{name}"')
    n_dims = struct.unpack('<I', f.read(4))[0]
    print(f'n_dims: {n_dims}')
    for d in range(n_dims):
        dim = struct.unpack('<Q', f.read(8))[0]
        print(f'  dim[{d}]: {dim}')
    ttype = struct.unpack('<I', f.read(4))[0]
    print(f'type: {ttype}')
    offset = struct.unpack('<Q', f.read(8))[0]
    print(f'offset: {offset}')
