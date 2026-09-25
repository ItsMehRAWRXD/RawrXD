import struct, sys
path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'
with open(path, 'rb') as f:
    magic = f.read(4)
    print('magic:', magic)
    version = struct.unpack('<I', f.read(4))[0]
    print('version:', version)
    tensorCount = struct.unpack('<Q', f.read(8))[0]
    metaCount = struct.unpack('<Q', f.read(8))[0]
    print('tensorCount:', tensorCount, 'metaCount:', metaCount)
    for i in range(metaCount):
        keyLen = struct.unpack('<Q', f.read(8))[0]
        key = f.read(keyLen).decode('utf-8')
        vtype = struct.unpack('<I', f.read(4))[0]
        if vtype == 8: # STRING
            valLen = struct.unpack('<Q', f.read(8))[0]
            val = f.read(valLen).decode('utf-8')
            if 'tokens' in key and 'model' in key:
                print(f'{key}: {val}')
        elif vtype == 9: # ARRAY
            arrType = struct.unpack('<I', f.read(4))[0]
            arrLen = struct.unpack('<Q', f.read(8))[0]
            if key == 'tokenizer.ggml.tokens':
                print(f'=== {key} type={arrType} count={arrLen} ===')
                for j in range(min(20, arrLen)):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    s = f.read(sl)
                    print(f'  {j}: repr={repr(s)}')
                # skip to byte tokens ~256
                for j in range(20, 250):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    f.read(sl)
                for j in range(250, 260):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    s = f.read(sl)
                    print(f'  {j}: repr={repr(s)}')
                # skip to key tokens
                for j in range(260, 9000):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    f.read(sl)
                for j in range(9259, 9260):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    s = f.read(sl)
                    print(f'  {j}: repr={repr(s)}')
                for j in range(9260, 26000):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    f.read(sl)
                for j in range(26352, 26353):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    s = f.read(sl)
                    print(f'  {j}: repr={repr(s)}')
                for j in range(26353, 236000):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    f.read(sl)
                for j in range(236743, 236744):
                    sl = struct.unpack('<Q', f.read(8))[0]
                    s = f.read(sl)
                    print(f'  {j}: repr={repr(s)}')
                print('Done')
                break
            else:
                # skip array
                for _ in range(arrLen):
                    if arrType == 8:
                        sl = struct.unpack('<Q', f.read(8))[0]
                        f.read(sl)
                    elif arrType in (4,5,6,7):
                        if arrType == 7:
                            f.read(1)
                        else:
                            f.read(4)
                    elif arrType in (10,11,12):
                        f.read(8)
                    else:
                        print(f'unknown array type {arrType}')
                        break
        elif vtype == 0: f.read(1)
        elif vtype == 1: f.read(1)
        elif vtype == 2: f.read(2)
        elif vtype == 3: f.read(2)
        elif vtype == 4: f.read(4)
        elif vtype == 5: f.read(4)
        elif vtype == 6: f.read(4)
        elif vtype == 7: f.read(1)
        elif vtype == 10: f.read(8)
        elif vtype == 11: f.read(8)
        elif vtype == 12: f.read(8)
        else:
            print(f'unknown type {vtype} for key {key}')
