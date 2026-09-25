import gguf, sys, traceback

path = 'D:/rawrxd/gemma3-1b-Q2_K.gguf'
out_path = 'f:/~dev/tmp_gguf_official.txt'

try:
    r = gguf.GGUFReader(path)
    with open(out_path, 'w', encoding='utf-8') as out:
        out.write(f'Version: {r.version}\n')
        out.write(f'Fields: {len(r.fields)}\n')
        out.write(f'Tensors: {len(r.tensors)}\n')
        for key in sorted(r.fields):
            f = r.fields[key]
            parts = [str(v.data) for v in f.parts]
            val = parts[0] if len(parts)==1 else parts
            if any(k in key.lower() for k in ('rope','theta','window','arch','attention')):
                out.write(f'{key} = {val}\n')
        out.write('--- ALL KEYS ---\n')
        for key in sorted(r.fields)[:50]:
            out.write(key + '\n')
except Exception:
    with open(out_path, 'w', encoding='utf-8') as out:
        traceback.print_exc(file=out)
