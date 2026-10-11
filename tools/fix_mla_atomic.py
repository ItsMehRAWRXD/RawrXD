import io, sys

GRAPH = r'F:\rawrxd\src\deep2\modelgenie\universal_gguf.cpp'
EXEC = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'


def patch_graph():
    src = io.open(GRAPH, encoding='utf-8').read()
    if 'attn_norm"|' in src or "attn_norm\"|" in src:
        return 'graph already patched'

    old = """                o.op = Op::MlaDecompress; o.block = (int32_t)b;
                o.a = name(Role::AttnKvAMqa);
                o.b = name(Role::AttnKNorm);
                o.c = name(Role::AttnKvB);
                o.out = "kv";"""
    new = """                o.op = Op::MlaDecompress; o.block = (int32_t)b;
                o.a = name(Role::AttnKvAMqa);
                o.b = name(Role::AttnKNorm) + "|attn_norm";
                o.c = name(Role::AttnKvB);
                o.out = "kv";"""

    if old not in src:
        return 'graph anchor missing'
    src = src.replace(old, new, 1)
    io.open(GRAPH, 'w', encoding='utf-8', newline='\n').write(src)
    return 'graph patched'


def patch_exec():
    src = io.open(EXEC, encoding='utf-8').read()
    if 'actName' in src:
        return 'exec already patched'

    # 1. split mla.b into weight name | activation name
    old1 = """    if (mla.a < 0 || mla.b < 0 || mla.c < 0) { err = "mla: missing weights"; return false; }
    const TensorRec& kvA = tensors_[(size_t)mla.a];
    const TensorRec& norm = tensors_[(size_t)mla.b];
    const TensorRec& kvB = tensors_[(size_t)mla.c];"""
    new1 = """    if (mla.a < 0 || mla.b < 0 || mla.c < 0) { err = "mla: missing weights"; return false; }
    const TensorRec& kvA = tensors_[(size_t)mla.a];
    int32_t normSlot = mla.b;
    std::string mlaActName;
    {
        const std::string& bn = mla.bName;
        const size_t bar = bn.find('|');
        if (bar != std::string::npos) {
            mlaActName = bn.substr(bar + 1);
            const std::string wantWeight = bn.substr(0, bar);
            for (size_t i = 0; i < tensors_.size(); ++i) {
                if (tensors_[i].name == wantWeight) { normSlot = (int32_t)i; break; }
            }
        }
    }
    const TensorRec& norm = tensors_[(size_t)normSlot];
    const TensorRec& kvB = tensors_[(size_t)mla.c];"""
    if old1 not in src:
        return 'exec anchor 1 missing'
    src = src.replace(old1, new1, 1)

    # 2. dispatch: resolve the activation from the arena instead of falling
    #    back to the running hidden vector (which is q by then).
    old2 = "                if (!OpMlaDecompress(in, xi, k, v, position, e)) { last_error_ = e; return false; }"
    new2 = """                {
                    std::vector<float> mlaIn;
                    std::string an;
                    const size_t bar = in.bName.find('|');
                    if (bar != std::string::npos) an = in.bName.substr(bar + 1);
                    auto fit = act.find(an);
                    if (fit != act.end()) mlaIn = fit->second;
                    if (mlaIn.empty()) mlaIn = xi;   // declared input as fallback
                    if (!OpMlaDecompress(in, mlaIn, k, v, position, e)) { last_error_ = e; return false; }
                }"""
    if old2 not in src:
        return 'exec anchor 2 missing'
    src = src.replace(old2, new2, 1)

    io.open(EXEC, 'w', encoding='utf-8', newline='\n').write(src)
    return 'exec patched'


r1 = patch_graph()
r2 = patch_exec()
print(r1)
print(r2)
