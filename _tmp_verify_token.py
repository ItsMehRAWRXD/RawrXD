from gguf import GGUFReader
r = GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')
t = r.fields['tokenizer.ggml.tokens']
print('token 245836:', repr(t.parts[245836]))
print('decoded:', t.parts[245836].decode('utf-8'))
