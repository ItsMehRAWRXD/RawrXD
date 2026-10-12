import io, re, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

# remove previous arena trace
src = re.sub(r'            case OpKind::LmHead: \{ /\* ARENATRACE \*/\n(                if \(arenaTrace\) \{.*?\n                \}\n)', r'            case OpKind::LmHead: {\n', src, flags=re.S)
src = src.replace('    static const bool arenaTrace = (std::getenv("RR_TRACE_ARENA") != nullptr); \n', '')

if 'SCORE_TRACE' in src:
    print('already'); sys.exit(0)

# Trace after every op, printing op name, outName and the resulting L2. This
# gives the first place where the value goes wrong.
old = '''    for (size_t pc = 0; pc < program_.size(); ++pc) {
        const auto& in = program_[pc];
        const std::vector<float>& xi = resolveIn(in);'''
new = '''    static const bool scoreTrace = (std::getenv("RR_TRACE_SCORE") != nullptr); /* SCORE_TRACE */
    size_t traceBudget = 40;
    for (size_t pc = 0; pc < program_.size(); ++pc) {
        const auto& in = program_[pc];
        const std::vector<float>& xi = resolveIn(in);
        if (scoreTrace && traceBudget > 0) {
            --traceBudget;
            std::fprintf(stderr, "  #%zu %-14s in=%-10s out=%-10s hiddenL2=%.6f\\n",
                         pc, OpKindName(in.op),
                         in.aName.empty() ? "<hidden>" : in.aName.c_str(),
                         in.outName.empty() ? "<hidden>" : in.outName.c_str(), hidden_.size());
        }'''
if old not in src:
    print('anchor missing'); sys.exit(1)
src = src.replace(old, new, 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
