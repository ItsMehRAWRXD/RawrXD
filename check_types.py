import struct

path = 'F:/models/Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf'
with open(path, 'rb') as f:
    magic = f.read(4)
    version = struct.unpack('<I', f.read(4))[0]
    tc = struct.unpack('<Q', f.read(8))[0]
    kc = struct.unpack('<Q', f.read(8))[0]
    print(f'Magic={magic} ver={version} tc={tc} kc={kc}')

    for i in range(kc):
        kl = struct.unpack('<Q', f.read(8))[0]
        f.seek(kl, 1)
        vt = struct.unpack('<I', f.read(4))[0]
        if vt == 0: f.seek(1, 1)
        elif vt == 1: f.seek(2, 1)
        elif vt == 2: f.seek(4, 1)
        elif vt == 3: f.seek(8, 1)
        elif vt == 4: f.seek(1, 1)
        elif vt == 5: f.seek(4, 1)
        elif vt == 6: f.seek(8, 1)
        elif vt == 7: f.seek(1, 1)
        elif vt == 8:
            sl = struct.unpack('<Q', f.read(8))[0]
            f.seek(sl, 1)
        elif vt == 9:
            at = struct.unpack('<I', f.read(4))[0]
            al = struct.unpack('<Q', f.read(8))[0]
            sz = {0:1,1:1,4:1,5:1,6:1,7:1,2:2,8:2,3:4,9:4,10:8,11:8}.get(at,1)
            f.seek(al*sz, 1)
        elif vt == 10: f.seek(8, 1)
        elif vt == 11: f.seek(8, 1)

    types = {}
    for i in range(tc):
        nl = struct.unpack('<Q', f.read(8))[0]
        f.seek(nl, 1)
        dims = struct.unpack('<I', f.read(4))[0]
        for _ in range(dims): f.seek(8, 1)
        dtype = struct.unpack('<I', f.read(4))[0]
        types[dtype] = types.get(dtype, 0) + 1

type_names = {0:'F32',1:'F16',2:'Q4_0',3:'Q4_1',6:'Q5_0',7:'Q5_1',8:'Q8_0',9:'Q8_1',10:'Q2_K',11:'Q3_K',12:'Q4_K',13:'Q5_K',14:'Q6_K',15:'Q8_K'}
print('Quant types:')
for k,v in types.items():
    print(f'  {k} ({type_names.get(k,chr(63))}): {v} tensors')
