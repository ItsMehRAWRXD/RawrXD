import struct, json, sys

# Dump the emitted op list for block 0 by re-reading the graph from universal_gguf
# via a tiny trace: instead, print the ops in program order by parsing the built
# harness's runtime trace. The executor prints nothing, so instrument by env var.
p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = open(p, encoding='utf-8').read()

# Add an env-gated op trace to the dispatch loop.
if 'RR_TRACE_OPS' not in src:
    anchor = '            switch (in.op) {'
    if anchor not in src:
        print('anchor missing'); sys.exit(1)
    new = (
        '            if (traceOps) {\n'
        '                std::fprintf(stderr, "  op #%zu blk=%d %s a=\'%s\' b=\'%s\' out=\'%s\' hidden=%zu\\n",\n'
        '                            pc, in.block, OpKindName(in.op),\n'
        '                            in.aName.c_str(), in.bName.c_str(), in.outName.c_str(),\n'
        '                            hidden_.size());\n'
        '            }\n'
    )
    src = src.replace(anchor, new + anchor, 1)
    # declare traceOps near act
    src = src.replace(
        'std::unordered_map<std::string, std::vector<float>> act;',
        'std::unordered_map<std::string, std::vector<float>> act;\n'
        '    static const bool traceOps = (std::getenv("RR_TRACE_OPS") != nullptr);', 1)
    open(p, 'w', encoding='utf-8', newline='\n').write(src)
    print('patched')
else:
    print('already patched')
