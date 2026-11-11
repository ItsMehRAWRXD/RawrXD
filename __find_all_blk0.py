import struct

path = 'F:/rawrxd/nemotron-bolt.gguf'
with open(path, 'rb') as f:
    magic = f.read(4)
    version = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_meta = struct.unpack('<Q', f.read(8))[0]
    
    for i in range(n_meta):
        key_len = struct.unpack('<Q', f.read(8))[0]
        key = f.read(key_len)
        val_type = struct.unpack('<I', f.read(4))[0]
        if val_type == 8:
            str_len = struct.unpack('<Q', f.read(8))[0]
            f.read(str_len)
        elif val_type == 9:
            arr_type = struct.unpack('<I', f.read(4))[0]
            arr_len = struct.unpack('<Q', f.read(8))[0]
            if arr_type == 8:
                for _ in range(arr_len):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    f.read(sl)
            else:
                elem_size = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1}.get(arr_type, 4)
                f.read(arr_len * elem_size)
        elif val_type == 6:
            f.read(4)
        elif val_type == 4:
            f.read(4)
        elif val_type == 5:
            f.read(4)
        elif val_type == 10:
            f.read(8)
        elif val_type == 11:
            f.read(8)
        elif val_type == 12:
            f.read(8)
        elif val_type in (0,1,7):
            f.read(1)
        elif val_type in (2,3):
            f.read(2)
    
    all_tensors = []
    for i in range(n_tensors):
        name_len = struct.unpack('<Q', f.read(8))[0]
        name = f.read(name_len).decode('utf-8', errors='replace')
        n_dims = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(n_dims)]
        ttype = struct.unpack('<I', f.read(4))[0]
        offset = struct.unpack('<Q', f.read(8))[0]
        if 'blk.0' in name:
            type_names = {0:'F32',1:'F16',2:'Q4_0',3:'Q4_1',6:'Q5_0',7:'Q5_1',8:'Q8_0',10:'Q2_K',11:'Q3_K',12:'Q4_K',13:'Q5_K',14:'Q6_K',15:'Q8_K',16:'IQ2_XXS',17:'IQ2_XS',18:'IQ2_S',30:'BF16',40:'NVFP4'}
            tname = type_names.get(ttype, f'TYPE_{ttype}')
            all_tensors.append(f'  {name} dims={dims} type={tname}({ttype})')
    
    for t in all_tensors:
        print(t)
    print(f'Total tensors for blk.0: {len(all_tensors)}')
