import sys

with open(r"F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp", "r", encoding="utf-8") as f:
    content = f.read()

old = """        // Then write all V (vSize = heads * value)
        for (size_t head = 0; head < heads; ++head) {
            const size_t src = head * (noRope + value) + noRope;
            const size_t dst = kSize + head * value;
            std::memcpy(output + dst, expanded.data() + src, value * sizeof(float));
        }
        return true;
"""

new = """            // V
            std::memcpy(output + dst + keyDim, expanded.data() + src + noRope, value * sizeof(float));
        }
        return true;
"""

if old in content:
    content = content.replace(old, new)
    with open(r"F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp", "w", encoding="utf-8") as f:
        f.write(content)
    print("Fixed MLA packing")
else:
    print("Pattern not found")
    # Debug: show what we're looking for
    idx = content.find("Then write all V")
    if idx >= 0:
        print("Found at index", idx)
        print("Context:", repr(content[idx:idx+500]))
    else:
        print("Not found at all")