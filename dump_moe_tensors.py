import struct

path = 'D:/rawrxd/synthetic_moe.gguf'
with open(path, 'rb') as f:
    magic = f.read(4)
    version = struct.unpack('<I', f.read(4))[0]
    nt = struct.unpack('<Q', f.read(8))[0]
    nm = struct.unpack('<Q', f.read(8))[0]
    print(f'version={version} nt={nt} nm={nm}')
    # skip metadata
    for mi in range(nm):
        pos = f.tell()
        key_len = struct.unpack('<Q', f.read(8))[0]
        key = f.read(key_len).decode('utf-8', errors='replace')
        dtype = struct.unpack('<I', f.read(4))[0]
        if dtype == 4: f.read(4)
        elif dtype == 5: f.read(4)
        elif dtype == 6: f.read(4)
        elif dtype == 7: f.read(1)
        elif dtype == 8:
            slen = struct.unpack('<Q', f.read(8))[0]
            f.read(slen)
        elif dtype == 9:
            atype = struct.unpack('<I', f.read(4))[0]
            alen = struct.unpack('<Q', f.read(8))[0]
            sz = {1:1,2:1,3:2,4:4,5:4,6:4,7:1,8:8,9:8,10:4,11:4,12:8}.get(atype,4)
            f.seek(alen * sz, 1)
        elif dtype == 10: f.read(8)
        elif dtype == 11: f.read(8)
        elif dtype == 12: f.read(8)
        else: f.read(4)
        print(f'  meta {mi}: {key} dtype={dtype} pos={pos}')
    # read tensor info
    for i in range(nt):
        name_len = struct.unpack('<Q', f.read(8))[0]
        if name_len > 1000:
            print(f'ABORT: name_len={name_len} at pos={f.tell()}')
            break
        name = f.read(name_len).decode('utf-8', errors='replace')
        ndims = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(ndims)]
        dtype = struct.unpack('<I', f.read(4))[0]
        offset = struct.unpack('<Q', f.read(8))[0]
        extra = struct.unpack('<Q', f.read(8))[0]
        print(f'tensor {i}: name="{name}" dims={dims} dtype={dtype} offset={offset}')
