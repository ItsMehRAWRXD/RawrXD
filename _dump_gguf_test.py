import gguf
path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'
reader = gguf.GGUFReader(path, 'r')
print('Tensors count:', len(reader.tensors))
for i, t in enumerate(reader.tensors):
    print(i, t.name, list(t.shape))
    if i > 10:
        break
