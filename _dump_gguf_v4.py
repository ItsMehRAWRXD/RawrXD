import struct

path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'
out_path = r'f:\~dev\tmp_gguf_keys.txt'

with open(path, 'rb') as f, open(out_path, 'w', encoding='utf-8') as out:
    magic = f.read(4)
    ver = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_kv = struct.unpack('<Q', f.read(8))[0]
    out.write(f'GGUF v{ver}, tensors={n_tensors}, kv={n_kv}\n')
    out.write(f'Header ends at offset {f.tell()}\n')

    # File appears to have metadata immediately after header (non-standard layout)
    # Let's just read what we find
    for i in range(n_kv + n_tensors + 50):
        pos = f.tell()
        try:
            kv_type = struct.unpack('<I', f.read(4))[0]
        except:
            break
        try:
            key_len = struct.unpack('<Q', f.read(8))[0]
            if key_len > 1000 or key_len == 0:
                # Not a metadata key, skip back
                f.seek(pos)
                break
            key = f.read(key_len).decode('utf-8', errors='replace')
            if any(k in key.lower() for k in ('rope','theta','window','arch','attention','head_count','key_length','layer_norm','qk','kv_per_head')):
                out.write(f'pos={pos} type={kv_type} key={key}\n')
            # skip value
            if kv_type == 0: f.seek(4,1)
            elif kv_type == 1: f.seek(4,1)
            elif kv_type == 2: f.seek(4,1)
            elif kv_type == 3: f.seek(1,1)
            elif kv_type == 4:
                slen = struct.unpack('<Q', f.read(8))[0]
                f.seek(slen,1)
            elif kv_type == 5:
                atype = struct.unpack('<I', f.read(4))[0]
                alen = struct.unpack('<Q', f.read(8))[0]
                if atype == 4:
                    for _ in range(alen):
                        slen = struct.unpack('<Q', f.read(8))[0]
                        f.seek(slen,1)
                else:
                    sz = {0:4,1:4,2:4,3:1,6:8,7:8,8:8,9:4,10:4,11:8,12:1}.get(atype,4)
                    f.seek(alen*sz,1)
            elif kv_type in (6,7): f.seek(8,1)
            elif kv_type == 8: f.seek(8,1)
            elif kv_type in (9,10): f.seek(4,1)
            elif kv_type == 11: f.seek(8,1)
            elif kv_type == 12: f.seek(1,1)
            else:
                out.write(f'  Unknown kv_type {kv_type}, stopping\n')
                break
        except Exception as e:
            out.write(f'Error at pos {pos}: {e}\n')
            break

    out.write(f'Final pos: {f.tell()}\n')
