import struct, sys
path = r'F:\~dev\rawrxd\src\core\test_tiny_with_vocab.gguf'
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
        if vtype == 0:   # UINT8
            val = struct.unpack('<B', f.read(1))[0]
        elif vtype == 1: # INT8
            val = struct.unpack('<b', f.read(1))[0]
        elif vtype == 2: # UINT16
            val = struct.unpack('<H', f.read(2))[0]
        elif vtype == 3: # INT16
            val = struct.unpack('<h', f.read(2))[0]
        elif vtype == 4: # UINT32
            val = struct.unpack('<I', f.read(4))[0]
        elif vtype == 5: # INT32
            val = struct.unpack('<i', f.read(4))[0]
        elif vtype == 6: # FLOAT32
            val = struct.unpack('<f', f.read(4))[0]
        elif vtype == 7: # BOOL
            val = struct.unpack('<?', f.read(1))[0]
        elif vtype == 8: # STRING
            valLen = struct.unpack('<Q', f.read(8))[0]
            val = f.read(valLen).decode('utf-8')
        elif vtype == 9: # ARRAY
            arrType = struct.unpack('<I', f.read(4))[0]
            arrLen = struct.unpack('<Q', f.read(8))[0]
            val = f'ARRAY[type={arrType},len={arrLen}]'
            # skip array content naively
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
        elif vtype == 10: # UINT64
            val = struct.unpack('<Q', f.read(8))[0]
        elif vtype == 11: # INT64
            val = struct.unpack('<q', f.read(8))[0]
        elif vtype == 12: # FLOAT64
            val = struct.unpack('<d', f.read(8))[0]
        else:
            print(f'unknown type {vtype} for key {key}')
            break
        print(f'  [{i}] {key} = type={vtype} val={val}')
    pos = f.tell()
    align = 32
    pad = (align - (pos % align)) % align
    if pad:
        f.read(pad)
    print('--- tensor names ---')
    for i in range(tensorCount):
        tnameLen = struct.unpack('<Q', f.read(8))[0]
        tname = f.read(tnameLen).decode('utf-8')
        print(i, tname)
        nDims = struct.unpack('<I', f.read(4))[0]
        for d in range(nDims):
            f.read(8)
        f.read(4) # type
        f.read(8) # offset
