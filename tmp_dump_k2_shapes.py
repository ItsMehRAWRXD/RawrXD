import struct, sys

path = sys.argv[1] if len(sys.argv) > 1 else r"F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf"

with open(path, 'rb') as f:
    magic = f.read(4)
    assert magic == b'GGUF', magic
    version = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_meta = struct.unpack('<Q', f.read(8))[0]

    alignment = 32
    for i in range(n_meta):
        key_len = struct.unpack('<Q', f.read(8))[0]
        key = f.read(key_len).decode('utf-8', 'replace')
        val_type = struct.unpack('<I', f.read(4))[0]
        def scalar(t):
            if t == 0: return struct.unpack('<B', f.read(1))[0]
            if t == 1: return struct.unpack('<b', f.read(1))[0]
            if t == 2: return struct.unpack('<H', f.read(2))[0]
            if t == 3: return struct.unpack('<h', f.read(2))[0]
            if t == 4: return struct.unpack('<I', f.read(4))[0]
            if t == 5: return struct.unpack('<i', f.read(4))[0]
            if t == 6: return struct.unpack('<f', f.read(4))[0]
            if t == 7: return struct.unpack('<B', f.read(1))[0] != 0
            if t == 8:
                sl = struct.unpack('<Q', f.read(8))[0]; return f.read(sl).decode('utf-8', 'replace')
            if t == 9:
                at = struct.unpack('<I', f.read(4))[0]; n = struct.unpack('<Q', f.read(8))[0]
                es = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1}.get(at, 4)
                f.read(n * es); return f"[array {at} x{n}]"
            if t == 10: return struct.unpack('<Q', f.read(8))[0]
            if t == 11: return struct.unpack('<q', f.read(8))[0]
            if t == 12: return struct.unpack('<d', f.read(8))[0]
            f.read(4); return f"(type {t})"
        val = scalar(val_type)
        if key == "general.alignment":
            alignment = val

    tensors = []
    for i in range(n_tensors):
        nlen = struct.unpack('<Q', f.read(8))[0]
        name = f.read(nlen).decode('utf-8', 'replace')
        ndims = struct.unpack('<I', f.read(4))[0]
        dims = list(struct.unpack(f'<{ndims}Q', f.read(8 * ndims)))
        ttype = struct.unpack('<I', f.read(4))[0]
        offset = struct.unpack('<Q', f.read(8))[0]
        tensors.append((name, dims, ttype, offset))

    TYPE_NAMES = {0:"F32",1:"F16",2:"Q4_0",3:"Q4_1",6:"Q5_0",7:"Q5_1",8:"Q8_0",
                  10:"Q2_K",11:"Q3_K",12:"Q4_K",13:"Q5_K",14:"Q6_K",15:"Q8_K",
                  16:"IQ2_XXS",24:"I8",25:"I16",26:"I32",27:"I64",28:"F64",30:"BF16",40:"NVFP4"}
    BLOCK = {0:(1,4),1:(1,2),2:(32,18),3:(32,20),6:(32,22),7:(32,24),8:(32,34),
             10:(256,84),11:(256,110),12:(256,144),13:(256,176),14:(256,210),
             15:(256,292),16:(256,66),24:(1,1),25:(1,2),26:(1,4),27:(1,8),28:(1,8),30:(1,2),40:(64,36)}

    wanted = [t for t in tensors if "ffn" in t[0] and ("exps" in t[0] or "shexp" in t[0] or "inp" in t[0] or "probs" in t[0])]
    print(f"alignment={alignment} n_tensors={n_tensors}")
    print(f"\n{len(wanted)} ffn-related tensors in shard 1:")
    for name, dims, ttype, offset in wanted:
        be, bb = BLOCK.get(ttype, (0, 0))
        rows = 1
        for d in dims[1:]: rows *= d
        blocks = (dims[0] + be - 1) // be if be else 0
        calc = blocks * bb * rows if be else None
        print(f"{name:46s} type={TYPE_NAMES.get(ttype, ttype):7s} dims={dims} offset={offset} calc_bytes={calc}")

    print("\nAll 'ffn' tensor names (shard 1):")
    for name, dims, ttype, offset in tensors:
        if "ffn" in name:
            print(f"  {name} dims={dims} type={TYPE_NAMES.get(ttype, ttype)}")
