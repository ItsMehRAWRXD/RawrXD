import io

p = r'F:\rawrxd\src\deep2\modelgenie\universal_gguf.cpp'
lines = io.open(p, encoding='utf-8').read().splitlines(keepends=True)
assert lines[722].strip() == 'o.a = "attn_norm";', repr(lines[722])
# a/b/c are all weight slots for OpMlaDecompress; the activation this op consumes
# rides in o.detail so the executor can resolve it from the arena explicitly.
lines[722] = '                o.a = name(Role::AttnKvAMqa);\n'
lines.insert(725, '                o.detail = "attn_norm";   // activation operand, resolved by executor\n')
io.open(p, 'w', encoding='utf-8', newline='\n').write(''.join(lines))
print('graph patched: a=kv_a_mqa weight, detail=activation name')
