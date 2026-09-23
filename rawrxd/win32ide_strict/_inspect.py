import struct
path = r'F:\~dev\rawrxd\src\core\test_tiny_with_vocab.gguf'
data = open(path, 'rb').read()
pos = 24
meta_count = 11
for i in range(meta_count):
    key_len, = struct.unpack_from('<Q', data, pos); pos += 8
    key = data[pos:pos+key_len].decode('utf-8'); pos += key_len
    val_type, = struct.unpack_from('<I', data, pos); pos += 4
    if val_type == 8:
        str_len, = struct.unpack_from('<Q', data, pos); pos += 8
        val = data[pos:pos+str_len].decode('utf-8', errors='replace'); pos += str_len
        print(f'{key} = \"{val}\"')
    elif val_type == 4 or val_type == 5:
        val, = struct.unpack_from('<i', data, pos); pos += 4
        print(f'{key} = {val}')
    elif val_type == 6:
        val, = struct.unpack_from('<f', data, pos); pos += 4
        print(f'{key} = {val}')
    elif val_type == 10:
        val, = struct.unpack_from('<Q', data, pos); pos += 8
        print(f'{key} = {val}')
    elif val_type == 9:
        arr_type, = struct.unpack_from('<I', data, pos); pos += 4
        arr_len, = struct.unpack_from('<Q', data, pos); pos += 8
        print(f'{key} = array[{arr_len}] type={arr_type}')
        if arr_type == 8:
            for _ in range(arr_len):
                sl, = struct.unpack_from('<Q', data, pos); pos += 8
                pos += sl
        elif arr_type == 4 or arr_type == 5:
            pos += arr_len * 4
        elif arr_type == 10:
            pos += arr_len * 8
        elif arr_type == 6:
            pos += arr_len * 4
        else:
            print(f'  skipping unknown array type {arr_type}')
            break
    else:
        print(f'{key} = unknown_type({val_type})')
        pos += 4

print('\n--- Tensor info ---')
for t in range(21):
    name_len, = struct.unpack_from('<Q', data, pos); pos += 8
    name = data[pos:pos+name_len].decode('utf-8'); pos += name_len
    n_dims, = struct.unpack_from('<I', data, pos); pos += 4
    dims = []
    for _ in range(n_dims):
        d, = struct.unpack_from('<Q', data, pos); pos += 8
        dims.append(d)
    dtype, = struct.unpack_from('<I', data, pos); pos += 4
    offset, = struct.unpack_from('<Q', data, pos); pos += 8
    print(f'{name}: {dims}')
