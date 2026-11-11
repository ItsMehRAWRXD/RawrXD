import io, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

if 'HIDDEN_TRACE' in src:
    print('already patched'); sys.exit(0)

# add helpers inside ExecuteToken, then trace after embedding and at LmHead
old = ('    const int32_t embSlot = slot_by_name_["token_embd.weight"];')
new = ('    static const bool htrace = (std::getenv("RR_TRACE_HIDDEN") != nullptr);\n'
       '    auto hl2 = [&]() { double s = 0; for (float v : hidden_) s += double(v)*v; return std::sqrt(s); };\n'
       '    auto hsum = [&]() { double s = 0; for (float v : hidden_) s += v; return s; };\n'
       '    const int32_t embSlot = slot_by_name_["token_embd.weight"];\n'
       '    // HIDDEN_TRACE')
if old not in src:
    print('anchor 1 missing'); sys.exit(1)
src = src.replace(old, new, 1)

# after embedding case (the 'break;' following hidden_l2_)
old2 = '                hidden_l2_ = std::sqrt(l2);\n                break;'
new2 = ('                hidden_l2_ = std::sqrt(l2);\n'
        '                if (htrace) std::fprintf(stderr, "    pos=%zu after_embed L2=%.6f sum=%.6f\\n", position, hl2(), hsum());\n'
        '                break;')
if old2 not in src:
    print('anchor 2 missing'); sys.exit(1)
src = src.replace(old2, new2, 1)

# at LmHead
old3 = '            case OpKind::LmHead: {\n                std::vector<float> y;'
new3 = ('            case OpKind::LmHead: {\n'
        '                if (htrace) std::fprintf(stderr, "    pos=%zu before_lmhead L2=%.6f sum=%.6f\\n", position, hl2(), hsum());\n'
        '                std::vector<float> y;')
if old3 not in src:
    print('anchor 3 missing'); sys.exit(1)
src = src.replace(old3, new3, 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
