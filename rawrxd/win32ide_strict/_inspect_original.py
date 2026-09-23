import struct

for label, path in [
    ("original", r'F:\~dev\rawrxd\src\core\test_tiny.gguf'),
    ("new", r'F:\~dev\rawrxd\src\core\test_tiny_with_vocab.gguf')
]:
    data = open(path, 'rb').read()
    pos = 24
    meta_count = 11
    for i in range(meta_count):
        key_len, = struct.unpack_from('<Q', data, pos); pos += 8
        key = data[pos:pos+key_len].decode('utf-8', errors='replace'); pos += key_len
        val_type, = struct.unpack_from('<I', data, pos); pos += 4
        if val_type == 8:
            str_len, = struct.unpack_from('<Q', data, pos); pos += 8
            pos += str_len
        elif val_type in (4,5):
            pos += 4
        elif val_type == 6:
            pos += 4
        elif val_type == 10:
            pos += 8
        elif val_type == 9:
            arr_type, = struct.unpack_from('<I', data, pos); pos += 4
            arr_len, = struct.unpack_from('<Q', data, pos); pos += 8
            if arr_type == 8:
                for _ in range(arr_len):
                    sl, = struct.unpack_from('<Q', data, pos); pos += 8
                    pos += sl
            elif arr_type in (4,5,6):
                pos += arr_len * 4
            elif arr_type == 10:
                pos += arr_len * 8
            else:
                break
        else:
            pos += 4

    print(f'\n=== {label}: {path} ===')
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
        if 'ffn' in name:
            print(f'  {name}: {dims}')
