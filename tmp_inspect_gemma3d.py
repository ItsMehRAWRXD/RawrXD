import gguf, sys
r = gguf.GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')

with open(r'f:\~dev\tmp_inspect_gemma3c_out.txt', 'w') as out:
    out.write(f'READER OK n_fields= {len(r.fields)}\n')

    # Find rope and theta fields
    for key in list(r.fields.keys()):
        if 'rope' in key.lower() or 'theta' in key.lower():
            f = r.fields[key]
            out.write(f"  {key}: types={f.types} data={f.data}\n")

    # Show architecture field
    arch_key = 'general.architecture'
    if arch_key in r.fields:
        out.write(f"  {arch_key}: {r.fields[arch_key].data}\n")

    # Show all gemma3-prefixed fields
    for key in list(r.fields.keys()):
        if key.startswith('gemma3'):
            f = r.fields[key]
            out.write(f"  {key}: types={f.types} data={f.data}\n")

    out.write('DONE\n')
