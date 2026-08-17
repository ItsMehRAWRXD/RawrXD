import struct

def read_gguf_meta(path):
    with open(path, 'rb') as f:
        magic = f.read(4)
        version = struct.unpack('<I', f.read(4))[0]
        n_tensors = struct.unpack('<Q', f.read(8))[0]
        n_meta = struct.unpack('<Q', f.read(8))[0]
        print(f'Magic: {magic}, Version: {version}')
        print(f'Tensors: {n_tensors}, Metadata: {n_meta}')
        
        for i in range(n_meta):
            key_len = struct.unpack('<Q', f.read(8))[0]
            key = f.read(key_len).decode('utf-8', errors='replace')
            val_type = struct.unpack('<I', f.read(4))[0]
            
            if val_type == 0:  # uint8
                val = struct.unpack('<B', f.read(1))[0]
            elif val_type == 1:  # int8
                val = struct.unpack('<b', f.read(1))[0]
            elif val_type == 2:  # uint16
                val = struct.unpack('<H', f.read(2))[0]
            elif val_type == 3:  # int16
                val = struct.unpack('<h', f.read(2))[0]
            elif val_type == 4:  # uint32
                val = struct.unpack('<I', f.read(4))[0]
            elif val_type == 5:  # int32
                val = struct.unpack('<i', f.read(4))[0]
            elif val_type == 6:  # float32
                val = struct.unpack('<f', f.read(4))[0]
            elif val_type == 7:  # bool
                val = struct.unpack('<B', f.read(1))[0] != 0
            elif val_type == 8:  # string
                str_len = struct.unpack('<Q', f.read(8))[0]
                val = f.read(str_len).decode('utf-8', errors='replace')
            elif val_type == 9:  # array
                arr_type = struct.unpack('<I', f.read(4))[0]
                arr_len = struct.unpack('<Q', f.read(8))[0]
                if arr_type == 4:  # uint32 array
                    val = [struct.unpack('<I', f.read(4))[0] for _ in range(arr_len)]
                elif arr_type == 8:  # string array
                    val = []
                    for _ in range(arr_len):
                        sl = struct.unpack('<Q', f.read(8))[0]
                        val.append(f.read(sl).decode('utf-8', errors='replace'))
                else:
                    # Skip unknown array types
                    elem_size = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1}.get(arr_type, 4)
                    f.read(arr_len * elem_size)
                    val = f'[array type={arr_type}]'
            else:
                val = f'(unknown type={val_type})'
            
            print(f'  {key} = {val}')

if __name__ == '__main__':
    read_gguf_meta('gemma3-1b-Q2_K.gguf')
