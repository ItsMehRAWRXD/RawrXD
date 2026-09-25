import gguf, sys, traceback

try:
    r = gguf.GGUFReader('D:/rawrxd/gemma3-1b-Q2_K.gguf')
    print('reader ok', file=sys.stderr)
    print('fields', len(r.fields), file=sys.stderr)
    for k in list(r.fields.keys())[:15]:
        print(k, file=sys.stderr)
except Exception:
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)
