import struct
import sys

def read_gguf(filepath):
    with open(filepath, 'rb') as f:
        magic = f.read(4)
        if magic != b'GGUF':
            print('Not a gguf file')
            return
        version = struct.unpack('<I', f.read(4))[0]
        tensors = struct.unpack('<Q', f.read(8))[0]
        kvs = struct.unpack('<Q', f.read(8))[0]
        
        def read_string(f):
            strlen = struct.unpack('<Q', f.read(8))[0]
            return f.read(strlen).decode('utf-8')
            
        def skip_val(f, val_type):
            if val_type == 0: f.read(1)    # UINT8
            elif val_type == 1: f.read(1)  # INT8
            elif val_type == 2: f.read(2)  # UINT16
            elif val_type == 3: f.read(2)  # INT16
            elif val_type == 4: f.read(4)  # UINT32
            elif val_type == 5: f.read(4)  # INT32
            elif val_type == 6: f.read(4)  # FLOAT32
            elif val_type == 7: f.read(1)  # BOOL
            elif val_type == 8: read_string(f) # STRING
            elif val_type == 9: # ARRAY
                arr_type = struct.unpack('<I', f.read(4))[0]
                arr_len = struct.unpack('<Q', f.read(8))[0]
                for _ in range(arr_len):
                    skip_val(f, arr_type)
            elif val_type == 10: f.read(8) # UINT64
            elif val_type == 11: f.read(8) # INT64
            elif val_type == 12: f.read(8) # FLOAT64
            
        for _ in range(kvs):
            read_string(f)
            val_type = struct.unpack('<I', f.read(4))[0]
            skip_val(f, val_type)
            
        print('Tensor Count:', tensors)
        print('First 20 tensors:')
        for i in range(min(20, tensors)):
            name = read_string(f)
            ndims = struct.unpack('<I', f.read(4))[0]
            dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(ndims)]
            ttype = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            dims_str = 'x'.join(map(str, dims))
            print(f'{name} | Type={ttype} | Dims={dims_str} | Offset={offset}')
            
read_gguf(r'D:\rawrxd\phi3-mini-Q2_K.gguf')
