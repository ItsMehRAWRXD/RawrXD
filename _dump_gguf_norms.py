import gguf
path = r'D:\rawrxd\gemma3-1b-Q2_K.gguf'
reader = gguf.GGUFReader(path, 'r')
for t in reader.tensors:
    if 'post' in t.name.lower() or 'ffw' in t.name.lower() or ('norm' in t.name.lower() and 'blk.0.' in t.name):
        print(t.name, 'shape=', list(t.shape))
# Print all blk.0 tensors to diagnose naming
print("--- ALL blk.0 tensors ---")
for t in reader.tensors:
    if 'blk.0.' in t.name:
        print(t.name, list(t.shape))
