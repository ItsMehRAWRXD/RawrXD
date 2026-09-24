import gguf, sys
r = gguf.GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')
print('READER OK n_fields=', len(r.fields), file=sys.stderr)

# Find rope and theta fields using dict keys
for key in list(r.fields.keys()):
    if 'rope' in key.lower() or 'theta' in key.lower():
        f = r.fields[key]
        print(f"  {key}: types={f.types} data={f.data}", file=sys.stderr)

# Show architecture field
arch_key = 'general.architecture'
if arch_key in r.fields:
    print(f"  {arch_key}: {r.fields[arch_key].data}", file=sys.stderr)

# Show all gemma3-prefixed fields
for key in list(r.fields.keys()):
    if key.startswith('gemma3'):
        f = r.fields[key]
        print(f"  {key}: types={f.types} data={f.data}", file=sys.stderr)

print('DONE', file=sys.stderr)
