import io, sys

p = r'F:\rawrxd\tools\deep2_runtime_dispatch.cpp'
src = io.open(p, encoding='utf-8').read()

if 'logitsJson' in src:
    print('already'); sys.exit(0)

if 'tokenIdsArg;\n' not in src:
    src = src.replace('    std::string tokenIdsArg;',
                      '    std::string tokenIdsArg;\n    std::string logitsJson;', 1)

src = src.replace('    else if (a == "--force-cpu") forceCpu = true;',
                  '    else if (a == "--force-cpu") forceCpu = true;\n'
                  '    else if (a == "--dump-logits" && i + 1 < argc) logitsJson = argv[++i];', 1)

anchor = '            Check(tokParity, "argmax token matches at EVERY position");'
if anchor not in src:
    print('anchor missing'); sys.exit(1)

patch = '''            if (!logitsJson.empty()) {
                FILE* f = std::fopen(logitsJson.c_str(), "wb");
                if (f) {
                    std::fprintf(f, "{\\\"positions\\\": %zu, \\\"argmax\\\": [", gpuT.size());
                    for (size_t s = 0; s < gpuT.size(); ++s)
                        std::fprintf(f, "%s%u", s ? "," : "", gpuT[s]);
                    std::fprintf(f, "], \\\"logits\\\": [");
                    for (size_t s = 0; s < gpuL.size(); ++s) {
                        if (s) std::fprintf(f, ",");
                        std::fprintf(f, "[");
                        const size_t n = std::min<size_t>(gpuL[s].size(), 8);
                        for (size_t i = 0; i < n; ++i)
                            std::fprintf(f, "%s%.8f", i ? "," : "", gpuL[s][i]);
                        std::fprintf(f, "]");
                    }
                    std::fprintf(f, "]}\\n");
                    std::fclose(f);
                }
            }
'''
src = src.replace(anchor, patch + anchor, 1)
io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
