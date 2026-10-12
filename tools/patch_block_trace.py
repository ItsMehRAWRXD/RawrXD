import io, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

if 'BLOCKTRACE' in src:
    print('already'); sys.exit(0)

# Print hidden L2 after each block's final residual (resid2).
old = '''            case OpKind::ResidualAdd: {'''
new = '''            case OpKind::ResidualAdd: {  // BLOCKTRACE'''
if old not in src:
    print('anchor missing'); sys.exit(1)

# Instead of instrumenting the switch, wrap the per-token call site:
# print hidden_ after every op whose outName == "resid2" by hooking the arena
# write at the end of ResidualAdd. Simpler: after the whole program loop.
anchor = '    return true;'
# find the return of ExecuteToken (last one) - patch the one after logits_.
target = '    logits_ = y;\n                break;\n            }'
if target not in src:
    print('target missing'); sys.exit(1)
new_target = '''    if (blkTrace) {
                    std::vector<std::string> keys;
                    for (auto& kv : act) if (kv.first.rfind("resid2", 0) == 0) keys.push_back(kv.first);
                    for (auto& kv : act) if (kv.first == "resid2") keys.push_back(kv.first);
                    std::printf("    [blk] pos=%zu resid2_snapshots=%zu L2=", position, act.count("resid2") ? 1 : 0);
                    auto it = act.find("resid2");
                    if (it != act.end()) { double s = 0; for (float v : it->second) s += double(v)*v; std::printf("%.6f\\n", std::sqrt(s)); }
                    else std::printf("none\\n");
                }
                logits_ = y;
                break;
            }'''
src = src.replace(target, new_target, 1)
src = src.replace(
    '    const int32_t embSlot = slot_by_name_["token_embd.weight"];',
    '    static const bool blkTrace = (std::getenv("RR_TRACE_BLOCK") != nullptr);\n'
    '    const int32_t embSlot = slot_by_name_["token_embd.weight"];', 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
