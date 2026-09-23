import gguf, sys
print("PYTHON RUNNING")
sys.stdout.flush()
r = gguf.GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')
print("FIELDS")
for k in list(r.fields.keys())[:40]:
    f = r.fields[k]
    print(k, f.types, 'len=', len(f.raw_data) if hasattr(f,'raw_data') else '?')
for t in r.tensors:
    if t.name == 'output.weight' or t.name == 'lm_head.weight':
        print('OUTPUT_TENSOR:', t.name, list(t.shape))
for t in r.tensors:
    if 'output_norm' in t.name:
        print('NORM_TENSOR:', t.name, list(t.shape))
