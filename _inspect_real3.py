import gguf
r = gguf.GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')
print('Arch:', r.fields['general.architecture'].contents() if 'general.architecture' in r.fields else 'MISSING')
print('Tokens field:', 'tokenizer.ggml.tokens' in r.fields)
if 'tokenizer.ggml.tokens' in r.fields:
    print('Token count:', len(r.fields['tokenizer.ggml.tokens'].contents()))
for t in r.tensors:
    if 'output.weight' in t.name or 'lm_head' in t.name:
        print('Has output tensor:', t.name)
