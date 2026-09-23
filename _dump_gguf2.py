import struct, sys

def dump_gguf(path):
    with open(path, 'rb') as f:
        # Header
        magic = f.read(4)
        version = struct.unpack('<I', f.read(4))[0]
        tc = struct.unpack('<Q', f.read(8))[0]
        mc = struct.unpack('<Q', f.read(8))[0]
        print(f'magic={magic}, version={version}, tensorCount={tc}, metaCount={mc}')
        
        # Metadata KV
        for i in range(mc):
            keyLen = struct.unpack('<Q', f.read(8))[0]
            key = f.read(keyLen).decode('utf-8')
            vtype = struct.unpack('<I', f.read(4))[0]
            
            if vtype == 0:   # UINT8
                f.read(1)
            elif vtype == 1: # INT8
                f.read(1)
            elif vtype == 2: # UINT16
                f.read(2)
            elif vtype == 3: # INT16
                f.read(2)
            elif vtype == 4: # UINT32
                f.read(4)
            elif vtype == 5: # INT32
                f.read(4)
            elif vtype == 6: # FLOAT32
                f.read(4)
            elif vtype == 7: # BOOL
                f.read(1)
            elif vtype == 8: # STRING
                sl = struct.unpack('<Q', f.read(8))[0]
                f.read(sl)
            elif vtype == 9: # ARRAY
                arrType = struct.unpack('<I', f.read(4))[0]
                arrLen = struct.unpack('<Q', f.read(8))[0]
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
                f.read(8)
            elif vtype == 11: # INT64
                f.read(8)
            elif vtype == 12: # FLOAT64
                f.read(8)
            else:
                print(f'unknown type {vtype} for key {key}')
                break
        
        pos = f.tell()
        print(f'pos after metadata: {pos}')
        
        # Try alignment padding
        align = 32
        pad = (align - (pos % align)) % align
        if pad:
            f.read(pad)
        print(f'pos after alignment: {f.tell()}')
        
        # Tensor info table
        for i in range(tc):
            tnameLen = struct.unpack('<Q', f.read(8))[0]
            if tnameLen > 1000 or tnameLen == 0:
                print(f'BAD tnameLen={tnameLen} at tensor {i}, pos={f.tell()-8}')
                break
            tname = f.read(tnameLen).decode('utf-8')
            nDims = struct.unpack('<I', f.read(4))[0]
            for _ in range(nDims):
                f.read(8)
            f.read(4) # type
            f.read(8) # offset
            print(f'  [{i}] {tname}')

if __name__ == '__main__':
    dump_gguf(r'F:\~dev\rawrxd\src\core\test_tiny_with_vocab.gguf')
