import io

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
lines = io.open(p, encoding='utf-8').read().splitlines(keepends=True)

# line 987 (1-indexed) is 'return true;'
assert lines[986].strip() == 'return true;', repr(lines[986])
idx = 986

check = (
    "    if (!unresolved_inputs_.empty()) {\n"
    "        last_error_ = \"graph referenced activations that were never produced: \";\n"
    "        for (size_t i = 0; i < unresolved_inputs_.size() && i < 4; ++i)\n"
    "            last_error_ += unresolved_inputs_[i] + \"; \";\n"
    "        return false;\n"
    "    }\n"
)

lines.insert(idx, check)
io.open(p, 'w', encoding='utf-8', newline='\n').write(''.join(lines))
print('inserted fail-closed check')
