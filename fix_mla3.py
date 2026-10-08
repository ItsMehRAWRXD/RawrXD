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

# Find the exact text
idx = content.find("Then write all V")
if idx >= 0:
    # Find the end of the block
    end_idx = content.find("return true;", idx)
    if end_idx >= 0:
        end_idx = content.find("\n", end_idx)
        if end_idx >= 0:
            actual_old = content[idx:end_idx+1]
            print("Actual old text:")
            print(repr(actual_old))
            
            if actual_old in content:
                content = content.replace(actual_old, new)
                with open(r"F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp", "w", encoding="utf-8") as f:
                    f.write(content)
                print("Fixed MLA packing")
            else:
                print("Actual old not found in content")
        else:
            print("Could not find end of block")
    else:
        print("Pattern not found")