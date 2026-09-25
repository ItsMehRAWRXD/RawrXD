import gguf, sys

r = gguf.GGUFReader('D:/rawrxd/gemma3-1b-Q2_K.gguf')
print('GGUF fields:', len(r.fields))
for key in sorted(r.fields):
    f = r.fields[key]
    parts = [str(v.data) for v in f.parts]
    val = parts[0] if len(parts)==1 else parts
    if any(k in key.lower() for k in ('rope','theta','window','arch','attention')):
        print(f'{key} = {val}')
