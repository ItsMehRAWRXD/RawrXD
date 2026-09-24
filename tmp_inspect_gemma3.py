import gguf, sys
r = gguf.GGUFReader(r'D:\rawrxd\gemma3-1b-Q2_K.gguf')

# Find rope and theta fields
rope = [k.name for k in r.fields if 'rope' in k.name.lower()]
theta = [k.name for k in r.fields if 'theta' in k.name.lower()]
print('Rope fields:', rope)
print('Theta fields:', theta)

# Show first 30 field names
print('First 30 fields:')
for k in list(r.fields.keys())[:30]:
    print(' ', k)

# Show gemma3. specific fields
gemma3_fields = [k.name for k in r.fields if k.name.startswith('gemma3')]
print('Gemma3-specific fields:', gemma3_fields[:20])

# Show all fields with value inspection for rope-related
for k in r.fields:
    if 'rope' in k.name.lower() or 'theta' in k.name.lower():
        f = r.fields[k]
        print(f"  {k.name}: types={f.types} data={f.data}")
