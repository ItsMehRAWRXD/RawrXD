import struct, sys
path = r'D:\rawrxd\synthetic_moe.gguf'
with open(path, 'rb') as f:
    magic = f.read(4)
    ver = struct.unpack('<I', f.read(4))[0]
    tc = struct.unpack('<Q', f.read(8))[0]
    mc = struct.unpack('<Q', f.read(8))[0]
    print(f'ver={ver} tc={tc} mc={mc}')
    for i in range(mc):
        kl = struct.unpack('<Q', f.read(8))[0]
        key = f.read(kl).decode('utf-8', errors='replace')
        vt = struct.unpack('<I', f.read(4))[0]
        if vt == 8:
            sl = struct.unpack('<Q', f.read(8))[0]
            val = f.read(sl).decode('utf-8', errors='replace')
            print(f'  {key} = "{val}"')
        elif vt == 9:
            et = struct.unpack('<I', f.read(4))[0]
            cnt = struct.unpack('<Q', f.read(8))[0]
            print(f'  {key} = [array type={et} count={cnt}]')
            for j in range(cnt):
                if et == 8:
                    sl = struct.unpack('<Q', f.read(8))[0]
                    f.seek(sl, 1)
                elif et == 4:
                    f.seek(4, 1)
                else:
                    f.seek(4, 1)
        elif vt == 4:
            v = struct.unpack('<I', f.read(4))[0]
            print(f'  {key} = {v}')
        elif vt == 6:
            v = struct.unpack('<f', f.read(4))[0]
            print(f'  {key} = {v}')
        else:
            print(f'  {key} = <vt={vt}>')
    print('Tensors:')
    for i in range(tc):
        tl = struct.unpack('<Q', f.read(8))[0]
        tname = f.read(tl).decode('utf-8', errors='replace')
        nd = struct.unpack('<I', f.read(4))[0]
        shape = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
        dt = struct.unpack('<I', f.read(4))[0]
        off = struct.unpack('<Q', f.read(8))[0]
        print(f'  {tname} shape={shape}')
