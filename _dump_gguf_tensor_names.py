import sys, gguf

path = sys.argv[1]
reader = gguf.GGUFReader(path)
for i, ti in enumerate(reader.tensors):
    name = str(ti.name)
    if i < 20 or 'expert' in name.lower() or 'moe' in name.lower() or 'gate' in name.lower() or 'ffn' in name.lower():
        print(f"[{i}] {name}  dims={list(ti.shape)}")
