from gguf import GGUFReader
r = GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')
tokens = r.fields['tokenizer.ggml.tokens'].parts
for i in range(250, 260):
    print(f'{i}: repr={repr(tokens[i])}')
print(f'26352: repr={repr(tokens[26352])}')
print(f'236743: repr={repr(tokens[236743])}')
print(f'9259: repr={repr(tokens[9259])}')
print(f'0: repr={repr(tokens[0])}')
print(f'1: repr={repr(tokens[1])}')
print(f'2: repr={repr(tokens[2])}')
print(f'3: repr={repr(tokens[3])}')
