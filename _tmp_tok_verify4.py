import struct
path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'
with open(path, 'rb') as f:
    f.read(4) # magic
    f.read(4) # version
    tensorCount = struct.unpack('<Q', f.read(8))[0]
    metaCount = struct.unpack('<Q', f.read(8))[0]
    for i in range(metaCount):
        keyLen = struct.unpack('<Q', f.read(8))[0]
        key = f.read(keyLen).decode('utf-8')
        vtype = struct.unpack('<I', f.read(4))[0]
        if key == 'tokenizer.ggml.tokens' and vtype == 9:
            arrType = struct.unpack('<I', f.read(4))[0]
            arrLen = struct.unpack('<Q', f.read(8))[0]
            print(f'arrLen={arrLen}')
            for j in range(arrLen):
                sl = struct.unpack('<Q', f.read(8))[0]
                s = f.read(sl)
                if j in [640, 1293, 9259, 26352, 33526, 236743]:
                    print(f'  {j}: repr={repr(s)} len={len(s)}')
            break
        else:
            if vtype == 8:
                valLen = struct.unpack('<Q', f.read(8))[0]
                f.read(valLen)
            elif vtype == 9:
                arrType = struct.unpack('<I', f.read(4))[0]
                arrLen = struct.unpack('<Q', f.read(8))[0]
                for _ in range(arrLen):
                    if arrType == 8:
                        sl = struct.unpack('<Q', f.read(8))[0]
                        f.read(sl)
                    elif arrType in (4,5,6,7):
                        if arrType == 7: f.read(1)
                        else: f.read(4)
                    elif arrType in (10,11,12):
                        f.read(8)
                    else:
                        print(f'unknown arrType {arrType}')
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
                print(f'unknown vtype {vtype} for key {key}')
