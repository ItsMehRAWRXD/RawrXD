import struct

p = r'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'

def read_tokens_at_indices(indices):
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
                results = {}
                for j in range(acount):
                    vlen = struct.unpack('<Q', f.read(8))[0]
                    token_bytes = f.read(vlen)
                    if j in indices:
                        results[j] = token_bytes
                        if len(results) == len(indices):
                            break
                return results
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
    return {}

# Inspect tokens from K2-008 "Hello world" encoding
indices = {19180, 23617, 137790}
results = read_tokens_at_indices(indices)
for idx in sorted(results.keys()):
    tb = results[idx]
    print(f'Token {idx}: raw = {tb!r}')
    print(f'         hex = {tb.hex()}')
    try:
        s = tb.decode('utf-8')
        print(f'         utf-8 = {s!r}')
    except Exception as e:
        print(f'         utf-8 FAILED: {e}')
    print()

# Also check if concatenating 19180 + 23617 makes sense
if 19180 in results and 23617 in results:
    combined = results[19180] + results[23617]
    print(f'Combined 19180+23617: raw = {combined!r}')
    try:
        s = combined.decode('utf-8')
        print(f'         utf-8 = {s!r}')
    except Exception as e:
        print(f'         utf-8 FAILED: {e}')
    print()

# Check a few tokens that look like they might be Chinese
# Let's sample tokens around the BOS/EOS area and some random ones
print('--- Sampling tokens for UTF-8 validity ---')
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
            invalid_count = 0
            empty_count = 0
            sample_tokens = []
            for j in range(min(acount, 100000)):
                vlen = struct.unpack('<Q', f.read(8))[0]
                token_bytes = f.read(vlen)
                if vlen == 0:
                    empty_count += 1
                try:
                    token_bytes.decode('utf-8')
                except:
                    invalid_count += 1
                if j < 20 or (j >= 163580 and j < 163600):
                    try:
                        s = token_bytes.decode('utf-8')
                        sample_tokens.append((j, s))
                    except:
                        sample_tokens.append((j, f'<INVALID:{token_bytes.hex()}>'))
            print(f'Total tokens: {acount}')
            print(f'Empty tokens: {empty_count}')
            print(f'Invalid UTF-8: {invalid_count}')
            print(f'Sample tokens:')
            for idx, s in sample_tokens:
                print(f'  [{idx}] {s!r}')
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
