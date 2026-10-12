import io, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

if 'MLADUMP' in src:
    print('already'); sys.exit(0)

# find the MlaDecompress execution box and add a dump of its outputs.
anchor = '                arena(in.outName.empty() ? std::string("kv") : in.outName) = k_out;'
if anchor not in src:
    # try other likely form
    for cand in ['k_out;', 'v_out;', 'MlaDecompress']:
        pass
    print('anchor missing; searching')
    import re
    for m in re.finditer(r'.*MlaDecompress.*', src):
        print(m.group(0)[:120])
    sys.exit(1)

src = src.replace(anchor, '                /* MLADUMP */\n' + anchor, 1)
io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('annotated')
