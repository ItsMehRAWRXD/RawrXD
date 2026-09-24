import gguf, sys
print('PYTHON IMPORT OK', file=sys.stderr)
r = gguf.GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')
print('READER OK n_fields=', len(r.fields), file=sys.stderr)
for k in list(r.fields.keys())[:50]:
    print(k, file=sys.stderr)
