import struct

path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'

# We'll read the tokenizer.ggml.tokens array and search for specific tokens
targets = [
    b'\xe2\x96\x81Hello',   # ▁Hello
    b'Hello',                # Hello (without prefix)
    b'\xe2\x96\x81',         # ▁ alone
    b'\xe2\x96\x81He',       # ▁He
    b'\xe2\x96\x81Hell',     # ▁Hell
    b'\xe2\x96\x81H',        # ▁H
]

target_indices = {repr(t): [] for t in targets}

with open(path, 'rb') as f:
    # Skip header
    f.read(4)  # magic
    f.read(4)  # version
    tensorCount = struct.unpack('<Q', f.read(8))[0]
    metaCount = struct.unpack('<Q', f.read(8))[0]
    
    for i in range(metaCount):
        keyLen = struct.unpack('<Q', f.read(8))[0]
        key = f.read(keyLen).decode('utf-8')
        vtype = struct.unpack('<I', f.read(4))[0]
        
        if key == 'tokenizer.ggml.tokens' and vtype == 9:
            arrType = struct.unpack('<I', f.read(4))[0]
            arrLen = struct.unpack('<Q', f.read(8))[0]
            print(f'tokens array type={arrType} count={arrLen}')
            for j in range(arrLen):
                sl = struct.unpack('<Q', f.read(8))[0]
                s = f.read(sl)
                for t in targets:
                    if s == t:
                        target_indices[repr(t)].append(j)
                        print(f'  FOUND {repr(t)} at index {j}')
            print('Done searching tokens')
            break
        else:
            # skip value
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

print('Summary:')
for t in targets:
    print(f'  {repr(t)}: indices={target_indices[repr(t)]}')
