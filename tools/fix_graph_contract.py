import io, sys

GRAPH = r'F:\rawrxd\src\deep2\modelgenie\universal_gguf.cpp'
EXEC = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'

# 1) Graph: a must be the activation, not the kv_a_mqa weight name. Drop the
#    pipe hack entirely - the executor's `a` IS the activation slot and `b`/`c`
#    are weight slots.
g = io.open(GRAPH, encoding='utf-8').read()
g = g.replace('                o.a = name(Role::AttnKvAMqa);',
              '                o.a = "attn_norm";')
g = g.replace('                o.b = name(Role::AttnKNorm) + "|attn_norm";',
              '                o.b = name(Role::AttnKNorm);')
io.open(GRAPH, 'w', encoding='utf-8', newline='\n').write(g)
print('graph: a=attn_norm, b=latent norm')

# 2) Executor: remove the pipe-splitting and arena-fallback plumbing added
#    earlier, restoring the conventional contract (a=activation, b/c=weights).
e = io.open(EXEC, encoding='utf-8').read()

if 'mlaActName' in e:
    start = e.find('    int32_t normSlot = mla.b;')
    end = e.find('    const TensorRec& kvB = tensors_[(size_t)mla.c];')
    if start >= 0 and end > start:
        e = e[:start] + '    const TensorRec& norm = tensors_[(size_t)mla.b];\n' + e[end:]
        print('exec: removed pipe splitting')

dispatch_old = """                {
                    std::vector<float> mlaIn;
                    std::string an;
                    const size_t bar = in.bName.find('|');
                    if (bar != std::string::npos) an = in.bName.substr(bar + 1);
                    auto fit = act.find(an);
                    if (fit != act.end()) mlaIn = fit->second;
                    if (mlaIn.empty()) mlaIn = xi;   // declared input as fallback
                    if (!OpMlaDecompress(in, mlaIn, k, v, position, e)) { last_error_ = e; return false; }
                }"""
dispatch_new = """                if (!OpMlaDecompress(in, xi, k, v, position, e)) { last_error_ = e; return false; }"""
if dispatch_old in e:
    e = e.replace(dispatch_old, dispatch_new, 1)
    print('exec: dispatch uses plain xi')

# 3) Router output name is "router_logits" but something references that name
#    without it ever being written. Find the Router emit and its out name.
io.open(EXEC, 'w', encoding='utf-8', newline='\n').write(e)

for i, l in enumerate(g.splitlines()):
    if 'Op::Router' in l and 'o.op' in l:
        print('graph router emit at line', i + 1)
        for j in range(i - 1, min(i + 6, len(l.splitlines()))):
            print('   ', g.splitlines()[j])
