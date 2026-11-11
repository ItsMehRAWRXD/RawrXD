import struct, numpy as np, gguf
MODEL = r'F:\rawrxd\llama3.2-3b-Q2_K.gguf'
reader = gguf.GGUFReader(MODEL)
for t in reader.tensors:
    if t.name == 'blk.0.ffn_down.weight':
        td = t
        break
b = bytes(td.data)
for bi in [26, 27, 28, 29, 30, 31]:
    o = bi * 110
    d = struct.unpack_from('<H', b, o)[0]
    val = np.frombuffer(struct.pack('<H', d), dtype=np.float16)[0]
    print(f'block {bi}: d bits={hex(d)} val={val}')
    print('   scales raw', b[o+98:o+110].hex())
