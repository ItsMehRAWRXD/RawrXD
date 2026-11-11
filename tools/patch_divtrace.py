import io, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

if 'DIVTRACE' in src:
    print('already'); sys.exit(0)

# Dump the per-block tensors for the divergence hunt. Gated by RR_DUMP_TENSORS
# and a position filter, written as raw f32 to a directory from RR_DUMP_DIR.
old = '''    const int32_t embSlot = slot_by_name_["token_embd.weight"];'''
new = '''    const int32_t embSlot = slot_by_name_["token_embd.weight"];
    static const bool dumpTensors = (std::getenv("RR_DUMP_TENSORS") != nullptr); /* DIVTRACE */
    static const int dumpLayer = []() {
        const char* e = std::getenv("RR_DUMP_LAYER");
        return e ? std::atoi(e) : 0;
    }();
    static const char* dumpDir = std::getenv("RR_DUMP_DIR");
    auto dumpVec = [&](const char* tag, const std::vector<float>& v) {
        if (!dumpTensors || !dumpDir) return;
        if (in_block_dump_ != (int)dumpLayer && in_block_dump_ >= 0) return;
        char path[1024];
        std::snprintf(path, sizeof(path), "%s/t_%s_pos%zu.bin", dumpDir, tag, position);
        FILE* f = std::fopen(path, "wb");
        if (f) {
            std::fwrite(v.data(), sizeof(float), v.size(), f);
            std::fclose(f);
        }
    };'''
if old not in src:
    print('anchor missing'); sys.exit(1)
src = src.replace(old, new, 1)

# helper member to know the current block in dumpVec
src = src.replace('    static const bool dumpTensors = (std::getenv("RR_DUMP_TENSORS") != nullptr); /* DIVTRACE */',
                  '    int in_block_dump_ = -1; /* DIVTRACE */\n    static const bool dumpTensors = (std::getenv("RR_DUMP_TENSORS") != nullptr);', 1)

# set in_block_dump_ at the top of each iteration
src = src.replace('''    for (size_t pc = 0; pc < program_.size(); ++pc) {
        const auto& in = program_[pc];''',
'''    for (size_t pc = 0; pc < program_.size(); ++pc) {
        const auto& in = program_[pc];
        if (dumpTensors) in_block_dump_ = in.block;''', 1)

# hook the interesting ops: RmsNorm, Linear, Attention, MlaDecompress, SwiGLU,
# ResidualAdd, LmHead. Add dumpVec after each writes its arena/out value.
src = src.replace('''                arena(in.outName.empty() ? std::string("rms") : in.outName) = y;
                hidden_ = y;''',
'''                arena(in.outName.empty() ? std::string("rms") : in.outName) = y;
                hidden_ = y;
                dumpVec("rms", y);''', 1)

src = src.replace('''                arena(in.outName.empty() ? std::string("attn") : in.outName) = y;
                hidden_ = y;''',
'''                arena(in.outName.empty() ? std::string("attn") : in.outName) = y;
                hidden_ = y;
                dumpVec("attnout", y);''', 1)

src = src.replace('''                arena(in.outName.empty() ? std::string("lin") : in.outName) = y;
                hidden_ = y;''',
'''                arena(in.outName.empty() ? std::string("lin") : in.outName) = y;
                hidden_ = y;
                dumpVec(("lin" + std::to_string(pc)).c_str(), y);''', 1)

src = src.replace('''                arena(dst) = y;
                break;
            }
            case OpKind::Router: {''',
'''                arena(dst) = y;
                dumpVec("swiglu", y);
                break;
            }
            case OpKind::Router: {''', 1)

src = src.replace('''                arena(in.outName.empty() ? std::string("resid") : in.outName) = y;
                hidden_ = y;''',
'''                arena(in.outName.empty() ? std::string("resid") : in.outName) = y;
                hidden_ = y;
                dumpVec(("resid" + std::to_string(pc)).c_str(), y);''', 1)

src = src.replace('''                logits_ = y;
                break;''',
'''                logits_ = y;
                dumpVec("logits", y);
                break;''', 1)

# cache k/v after attention writes them
src = src.replace('''    std::memcpy(V.data() + position * vW, v.data(), vW * sizeof(float));''',
'''    std::memcpy(V.data() + position * vW, v.data(), vW * sizeof(float));
    if (dumpTensors && in_block_dump_ == (int)dumpLayer) {
        dumpVec("knew", k); dumpVec("vnew", v);
    }''', 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
