import gguf
path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'
reader = gguf.GGUFReader(path, 'r')
for t in reader.tensors:
    if 'blk.0.' in t.name:
        print(t.name, list(t.shape))
