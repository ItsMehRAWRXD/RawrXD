import struct

p = r'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'
with open(p, 'rb') as f:
    magic = struct.unpack('<I', f.read(4))[0]
    ver = struct.unpack('<I', f.read(4))[0]
    tc = struct.unpack('<Q', f.read(8))[0]
    kvc = struct.unpack('<Q', f.read(8))[0]
    for i in range(kvc):
        slen = struct.unpack('<Q', f.read(8))[0]
        key = f.read(slen).decode('utf-8', errors='replace')
        vtype = struct.unpack('<I', f.read(4))[0]
        if key == 'tokenizer.ggml.tokens' and vtype == 9:
            etype = struct.unpack('<I', f.read(4))[0]
            acount = struct.unpack('<Q', f.read(8))[0]
            for j in range(acount):
                vlen = struct.unpack('<Q', f.read(8))[0]
                if j == 137790:
                    token_bytes = f.read(vlen)
                    print(f'Token {j}: raw bytes = {token_bytes!r}')
                    print(f'Token {j}: hex = {token_bytes.hex()}')
                    try:
                        decoded = token_bytes.decode('utf-8')
                        print(f'Token {j}: utf-8 decode = {decoded}')
                    except Exception as e:
                        print(f'Token {j}: utf-8 decode FAILED: {e}')
                    break
                else:
                    f.read(vlen)
            break
        else:
            if vtype == 8:
                vlen = struct.unpack('<Q', f.read(8))[0]
                f.read(vlen)
            elif vtype == 9:
                etype = struct.unpack('<I', f.read(4))[0]
                acount = struct.unpack('<Q', f.read(8))[0]
                for j in range(acount):
                    if etype == 8:
                        vlen = struct.unpack('<Q', f.read(8))[0]
                        f.read(vlen)
                    elif etype == 6:
                        f.read(4)
                    elif etype == 4:
                        f.read(4)
                    elif etype == 5:
                        f.read(4)
            elif vtype == 4:
                f.read(4)
            elif vtype == 5:
                f.read(4)
            elif vtype == 6:
                f.read(4)
            elif vtype == 10:
                f.read(8)
            elif vtype == 11:
                f.read(8)
            elif vtype == 0:
                f.read(1)
            elif vtype == 1:
                f.read(1)
            elif vtype == 7:
                f.read(1)
