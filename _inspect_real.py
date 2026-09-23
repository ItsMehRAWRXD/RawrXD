import gguf
r = gguf.GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')
print('Tensors:', len(r.tensors))
for t in r.tensors[:15]:
    print(' ', t.name, ':', list(t.shape))
print('...')
for t in r.tensors[-5:]:
    print(' ', t.name, ':', list(t.shape))
print()
for t in r.tensors:
    if 'embed' in t.name or 'token' in t.name.lower():
        print('Embed:', t.name, list(t.shape))
for t in r.tensors:
    if 'output' in t.name.lower() or 'lm_head' in t.name.lower():
        print('Output:', t.name, list(t.shape))
for t in r.tensors:
    if 'norm' in t.name.lower():
        print('Norm:', t.name, list(t.shape))
if 'general.architecture' in r.fields:
    print('Arch:', r.fields['general.architecture'].contents())
