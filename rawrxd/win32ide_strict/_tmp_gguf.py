import struct
path = r'F:\~dev\rawrxd\src\core\test_minimal.gguf'
data = open(path, 'rb').read()
pos = 0
magic, = struct.unpack_from('<I', data, pos); pos += 4
version, = struct.unpack_from('<I', data, pos); pos += 4
tensor_count, = struct.unpack_from('<Q', data, pos); pos += 8
meta_count, = struct.unpack_from('<Q', data, pos); pos += 8
print(f'Magic: {magic:08X}')
print(f'Version: {version}')
print(f'Tensor count: {tensor_count}')
print(f'Metadata count: {meta_count}')

def align8(p):
    return (p + 7) & ~7

TYPE_NAMES = {
    0: 'uint8', 1: 'int8', 2: 'uint16', 3: 'int16',
    4: 'uint32', 5: 'int32', 6: 'float32', 7: 'bool',
    8: 'string', 9: 'array', 10: 'uint64', 11: 'int64', 12: 'float64'
}

print('\n--- Metadata ---')
for i in range(meta_count):
    key_len, = struct.unpack_from('<Q', data, pos); pos += 8
    key = data[pos:pos+key_len].decode('utf-8'); pos += key_len
    val_type, = struct.unpack_from('<I', data, pos); pos += 4
    
    if val_type == 8:  # string
        str_len, = struct.unpack_from('<Q', data, pos); pos += 8
        val = data[pos:pos+str_len].decode('utf-8', errors='replace'); pos += str_len
    elif val_type == 10:  # uint64
        val, = struct.unpack_from('<Q', data, pos); pos += 8
    elif val_type == 4:  # uint32
        val, = struct.unpack_from('<I', data, pos); pos += 4
    elif val_type == 6:  # float32
        val, = struct.unpack_from('<f', data, pos); pos += 4
    elif val_type == 0:  # uint8
        val, = struct.unpack_from('<B', data, pos); pos += 1
    elif val_type == 1:  # int8
        val, = struct.unpack_from('<b', data, pos); pos += 1
    elif val_type == 2:  # uint16
        val, = struct.unpack_from('<H', data, pos); pos += 2
    elif val_type == 3:  # int16
        val, = struct.unpack_from('<h', data, pos); pos += 2
    elif val_type == 5:  # int32
        val, = struct.unpack_from('<i', data, pos); pos += 4
    elif val_type == 7:  # bool
        val, = struct.unpack_from('<B', data, pos); pos += 1
    elif val_type == 9:  # array
        arr_type, = struct.unpack_from('<I', data, pos); pos += 4
        arr_len, = struct.unpack_from('<Q', data, pos); pos += 8
        val = f'array[{arr_len}] of type {arr_type}'
        elem_sizes = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,8:8,10:8,11:8,12:8}
        if arr_type in elem_sizes:
            pos += arr_len * elem_sizes[arr_type]
        elif arr_type == 8:  # array of strings
            for _ in range(arr_len):
                sl, = struct.unpack_from('<Q', data, pos); pos += 8
                pos += sl
        else:
            print(f'Skipping unknown array type {arr_type}'); break
    elif val_type == 11:  # int64
        val, = struct.unpack_from('<q', data, pos); pos += 8
    elif val_type == 12:  # float64
        val, = struct.unpack_from('<d', data, pos); pos += 8
    else:
        print(f'Unknown type {val_type} for key {key}'); break
    
    print(f'  {key} = {repr(val)} (type {val_type})')
    pos = align8(pos)

print(f'\nPosition after metadata: {pos}')

print('\n--- Tensors ---')
for t in range(tensor_count):
    name_len, = struct.unpack_from('<Q', data, pos); pos += 8
    name = data[pos:pos+name_len].decode('utf-8'); pos += name_len
    n_dims, = struct.unpack_from('<I', data, pos); pos += 4
    dims = []
    for _ in range(n_dims):
        d, = struct.unpack_from('<Q', data, pos); pos += 8
        dims.append(d)
    tt, = struct.unpack_from('<I', data, pos); pos += 4
    offset, = struct.unpack_from('<Q', data, pos); pos += 8
    print(f'  {name}: shape={dims} type={tt} offset={offset}')

print(f'\nData offset start: {pos}')
print(f'File size: {len(data)}')
