import io, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

if 'DIVTRACE' in src:
    print('already'); sys.exit(0)

# 1. helpers + state declared before the program loop
loop_anchor = '''    for (size_t pc = 0; pc < program_.size(); ++pc) {
        const auto& in = program_[pc];'''
if loop_anchor not in src:
    print('loop anchor missing'); sys.exit(1)

helpers = '''    /* DIVTRACE */
    static const bool dumpTensors = (std::getenv("RR_DUMP_TENSORS") != nullptr);
    static const int dumpLayer = []() {
        const char* e = std::getenv("RR_DUMP_LAYER");
        return e ? std::atoi(e) : 0;
    }();
    static const char* dumpDir = std::getenv("RR_DUMP_DIR");
    int dumpBlock = -1;
    auto dumpVec = [&](const char* tag, const std::vector<float>& v) {
        if (!dumpTensors || !dumpDir) return;
        if (dumpBlock != dumpLayer) return;
        char path[1024];
        std::snprintf(path, sizeof(path), "%s/t_%s_pos%zu.bin", dumpDir, tag, position);
        FILE* f = std::fopen(path, "wb");
        if (f) { std::fwrite(v.data(), sizeof(float), v.size(), f); std::fclose(f); }
    };

'''
src = src.replace(loop_anchor, helpers + loop_anchor, 1)

# 2. track the current block each iteration
src = src.replace(loop_anchor + '\n',
                  loop_anchor + '\n        if (dumpTensors) dumpBlock = in.block;\n', 1)

# 3. dump hooks, placed exactly where values are produced.
hooks = [
    # MLA k/v
    ('''                if (!OpMlaDecompress(in, xi, k, v, position, e)) { last_error_ = e; return false; }
                arena(in.outName.empty() ? std::string("kv") : in.outName) = hidden_;''',
     '''                if (!OpMlaDecompress(in, xi, k, v, position, e)) { last_error_ = e; return false; }
                { std::string tk = "mla_k" + std::to_string(pc); std::string tv = "mla_v" + std::to_string(pc);
                  dumpVec(tk.c_str(), k); dumpVec(tv.c_str(), v); }
                arena(in.outName.empty() ? std::string("kv") : in.outName) = hidden_;'''),
    # q (Linear writes via the outName slot)
    ('''                arena(in.outName.empty() ? std::string("lin") : in.outName) = y;
                hidden_ = y;''',
     '''                { std::string t = "q" + std::to_string(pc); dumpVec(t.c_str(), y); }
                arena(in.outName.empty() ? std::string("lin") : in.outName) = y;
                hidden_ = y;'''),
    # attention out
    ('''                arena("attn") = y;''',
     '''                dumpVec("attn", y);
                arena("attn") = y;'''),
    # residual
    ('''                arena(in.outName.empty() ? std::string("resid") : in.outName) = y;''',
     '''                { std::string t = "resid" + std::to_string(pc); dumpVec(t.c_str(), y); }
                arena(in.outName.empty() ? std::string("resid") : in.outName) = y;'''),
    # logits
    ('''                logits_ = y;''',
     '''                dumpVec("logits", y);
                logits_ = y;'''),
]

for old, new in hooks:
    if old not in src:
        print('hook anchor missing:', old.strip()[:60])
        sys.exit(1)
    src = src.replace(old, new, 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched cleanly')
