import io, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

if 'unresolved_inputs_.clear();' in src:
    print('already patched')
    sys.exit(0)

old = "    hidden_.clear();\n    logits_.clear();\n    nonfinite_logits_ = 0;\n    hidden_l2_ = 0.0;"
new = ("    hidden_.clear();\n"
       "    logits_.clear();\n"
       "    nonfinite_logits_ = 0;\n"
       "    hidden_l2_ = 0.0;\n"
       "    unresolved_inputs_.clear();")
if old not in src:
    print('anchor 1 missing')
    sys.exit(1)
src = src.replace(old, new, 1)

# Reject the run if any named operand was unresolved.
marker = "\n// ---------------------------------------------------------------------------\n// Reset / accessors"
idx = src.find(marker)
if idx < 0:
    print('reset marker missing')
    sys.exit(1)

check = (
    "\n    if (!unresolved_inputs_.empty()) {\n"
    "        last_error_ = \"graph referenced activations that were never produced: \";\n"
    "        for (size_t i = 0; i < unresolved_inputs_.size() && i < 4; ++i)\n"
    "            last_error_ += unresolved_inputs_[i] + \"; \";\n"
    "        return false;\n"
    "    }\n"
)

# Insert the check just before the marker, i.e. at the end of ExecuteToken.
src = src[:idx] + check + src[idx:]
io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
