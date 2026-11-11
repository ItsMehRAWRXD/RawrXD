import io, sys

p = r'F:\rawrxd\tools\deep2_runtime_dispatch.cpp'
src = io.open(p, encoding='utf-8').read()

if 'enc dump' in src:
    print('already'); sys.exit(0)

old = '''        std::string back = DetokenizeWith(tk.tokens, enc.ids);'''
new = '''        // enc dump: show each token's literal text so round-trip loss is visible
        for (size_t i = 0; i < enc.ids.size(); ++i) {
            int32_t id = enc.ids[i];
            const char* ts = (id >= 0 && id < (int32_t)tk.tokens.size()) ? tk.tokens[id].c_str() : "<OOB>";
            std::printf("    tok[%2d] id=%7d text=\\"%s\\"\\n", i, id, ts);
        }
        std::string back = DetokenizeWith(tk.tokens, enc.ids);'''
if old not in src:
    print('anchor missing'); sys.exit(1)
src = src.replace(old, new, 1)
io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
