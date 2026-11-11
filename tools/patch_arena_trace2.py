import io, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

if 'ARENATRACE' in src:
    print('already'); sys.exit(0)

target = '            case OpKind::LmHead: {\n                std::vector<float> y;'
if target not in src:
    print('anchor missing'); sys.exit(1)

new = '''            case OpKind::LmHead: { /* ARENATRACE */
                if (arenaTrace) {
                    const char* keys[] = {"attn_norm","q","kv","attn_out","attn_proj","resid1",
                                          "ffn_norm","gate","up","swiglu","ffn_out","resid2","out_norm"};
                    for (const char* k : keys) {
                        auto it = act.find(k);
                        if (it == act.end()) { std::printf("    %-10s MISSING\\n", k); continue; }
                        double s = 0; float mn = 1e30f, mx = -1e30f;
                        for (float v : it->second) { s += double(v)*v; mn = std::min(mn, v); mx = std::max(mx, v); }
                        std::printf("    %-10s n=%zu L2=%.6f min=%.6f max=%.6f\\n", k, it->second.size(), std::sqrt(s), mn, mx);
                    }
                }
                std::vector<float> y;'''
src = src.replace(target, new, 1)
src = src.replace(
    '    const int32_t embSlot = slot_by_name_["token_embd.weight"];',
    '    static const bool arenaTrace = (std::getenv("RR_TRACE_ARENA") != nullptr); \n'
    '    const int32_t embSlot = slot_by_name_["token_embd.weight"];', 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
