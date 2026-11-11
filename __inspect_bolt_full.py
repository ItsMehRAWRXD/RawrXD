import struct, sys, codecs

path = 'F:/rawrxd/nemotron-bolt.gguf'
out = open('F:/rawrxd/__bolt_tensors.txt', 'w', encoding='utf-8')

with open(path, 'rb') as f:
    magic = f.read(4)
    version = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_meta = struct.unpack('<Q', f.read(8))[0]
    
    out.write(f'Magic: {magic}, Version: {version}\n')
    out.write(f'Tensors: {n_tensors}, Metadata: {n_meta}\n')
    
    for i in range(n_meta):
        key_len = struct.unpack('<Q', f.read(8))[0]
        key = f.read(key_len).decode('utf-8', errors='replace')
        val_type = struct.unpack('<I', f.read(4))[0]
        if val_type == 8:
            str_len = struct.unpack('<Q', f.read(8))[0]
            val = f.read(str_len).decode('utf-8', errors='replace')
        elif val_type == 9:
            arr_type = struct.unpack('<I', f.read(4))[0]
            arr_len = struct.unpack('<Q', f.read(8))[0]
            if arr_type == 8:
                val = []
                for _ in range(arr_len):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    val.append(f.read(sl).decode('utf-8', errors='replace'))
            else:
                elem_size = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1}.get(arr_type, 4)
                f.read(arr_len * elem_size)
                val = f'[array type={arr_type} len={arr_len}]'
        elif val_type == 6:
            val = struct.unpack('<f', f.read(4))[0]
        elif val_type == 4:
            val = struct.unpack('<I', f.read(4))[0]
        elif val_type == 5:
            val = struct.unpack('<i', f.read(4))[0]
        elif val_type == 10:
            val = struct.unpack('<Q', f.read(8))[0]
        elif val_type == 11:
            val = struct.unpack('<q', f.read(8))[0]
        elif val_type == 12:
            val = struct.unpack('<d', f.read(8))[0]
        else:
            val = f'(unknown type={val_type})'
            f.read(100)
        out.write(f'  {key} = {val}\n')
    
    out.write(f'\n--- Tensors ({n_tensors}) ---\n')
    for i in range(n_tensors):
        name_len = struct.unpack('<Q', f.read(8))[0]
        name = f.read(name_len).decode('utf-8', errors='replace')
        n_dims = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(n_dims)]
        ttype = struct.unpack('<I', f.read(4))[0]
        offset = struct.unpack('<Q', f.read(8))[0]
        type_names = {0:'F32',1:'F16',2:'Q4_0',3:'Q4_1',6:'Q5_0',7:'Q5_1',8:'Q8_0',10:'Q2_K',11:'Q3_K',12:'Q4_K',13:'Q5_K',14:'Q6_K',15:'Q8_K',16:'IQ2_XXS',17:'IQ2_XS',18:'IQ2_S',30:'BF16',40:'NVFP4'}
        tname = type_names.get(ttype, f'TYPE_{ttype}')
        out.write(f'  {i}: {name} dims={dims} type={tname}({ttype}) offset={offset}\n')
    
    out.close()
    print(f"Done. Wrote {n_tensors} tensors.")
