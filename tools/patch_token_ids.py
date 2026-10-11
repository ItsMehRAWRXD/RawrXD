import io, sys

p = r'F:\rawrxd\tools\deep2_runtime_dispatch.cpp'
src = io.open(p, encoding='utf-8').read()

if '--token-ids' in src:
    print('already'); sys.exit(0)

# add flag parse
src = src.replace('    else if (a == "--force-cpu") forceCpu = true;',
                  '    else if (a == "--force-cpu") forceCpu = true;\n'
                  '    else if (a == "--token-ids" && i + 1 < argc) tokenIdsArg = argv[++i];', 1)

src = src.replace('    bool verifyDequant = false;',
                  '    bool verifyDequant = false;\n    std::string tokenIdsArg;', 1)

# after prompt is tokenized (enc), if tokenIdsArg set, parse it into ids
anchor = '    // ---- [3] chat template'
if anchor not in src:
    print('anchor missing'); sys.exit(1)

patch = '''    if (!tokenIdsArg.empty()) {
        std::vector<int32_t> ids;
        const char* q = tokenIdsArg.c_str();
        while (*q) {
            char* end = nullptr;
            long v = std::strtol(q, &end, 10);
            if (end == q) { ++q; continue; }
            ids.push_back((int32_t)v);
            q = end;
        }
        if (ids.empty()) { std::fprintf(stderr, "no ids parsed\\n"); return 1; }
        enc.ids = ids;
        enc.ok = true;
        std::printf("using %zu explicit token ids\\n", ids.size());
    }

'''
src = src.replace(anchor, patch + anchor, 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
