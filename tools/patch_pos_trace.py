import io, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

if 'hidden_l2' in src:
    print('already has hidden_l2')
    sys.exit(0)

# hidden_l2_ is computed after the embedding. Print it per position plus at the
# end of the run, which distinguishes "state not advancing" from "state advances
# but attention collapses it".
anchor = '    hidden_.clear();\n    logits_.clear();'
if anchor not in src:
    print('anchor missing'); sys.exit(1)

new = ('    hidden_.clear();\n'
       '    logits_.clear();\n'
       '    if (traceAttn) std::fprintf(stderr, "  [pos] begin position=%zu token=%u\\n", position, token);')
src = src.replace(anchor, new, 1)

# also print at the very end, right before the return
anchor2 = '    return true;'
# patch the *final* success return of ExecuteToken (after logits are produced).
# Use the logits block instead.
anchor3 = 'arena(in.outName.empty() ? std::string("resid") : in.outName) = y;'
if anchor3 in src:
    pass

src = src.replace(
    '    static const bool traceOps = (std::getenv("RR_TRACE_OPS") != nullptr);',
    '    static const bool traceOps = (std::getenv("RR_TRACE_OPS") != nullptr);\n'
    '    static const bool traceAttn = (std::getenv("RR_TRACE_ATTN") != nullptr);', 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
