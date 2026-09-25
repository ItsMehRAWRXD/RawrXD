from gguf import GGUFReader
r = GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')
print('reader ok')
keys = list(r.fields.keys())[:5]
print('keys:', keys)
t = r.fields['tokenizer.ggml.tokens']
print('tokens type:', type(t))
print('parts len:', len(t.parts))
print('part 250:', repr(t.parts[250]))
print('part 255:', repr(t.parts[255]))
print('part 256:', repr(t.parts[256]))
print('part 257:', repr(t.parts[257]))
print('part 26352:', repr(t.parts[26352]))
print('part 236743:', repr(t.parts[236743]))
print('part 9259:', repr(t.parts[9259]))
print('part 0:', repr(t.parts[0]))
print('part 1:', repr(t.parts[1]))
print('part 2:', repr(t.parts[2]))
