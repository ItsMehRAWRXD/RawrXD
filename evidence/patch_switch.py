import re, sys

path = r"F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp"
with open(path, "rb") as f:
    raw = f.read()
had_crlf = b"\r\n" in raw
s = raw.decode("utf-8")
if had_crlf:
    s = s.replace("\r\n", "\n")

# Match the buggy metadata value-type switch (comment + switch through its close).
old_pattern = re.compile(
    r'// Skip value based on type.*?switch\s*\(\s*valueType\s*\)\s*\{.*?\n            \}',
    re.DOTALL
)

new_block = (
    "            // Skip value based on its gguf_type (src/gguf.h enum). value_type is a\n"
    "            // 4-byte int32 stored with NO padding; value data follows at once.\n"
    "            // Scalars are fixed-size; strings = uint64 len + bytes; arrays =\n"
    "            // elem_type(int32) + count(uint64) + count elements (string elements\n"
    "            // are length-prefixed). Patched: spec-correct value skip.\n"
    "            switch (valueType)\n"
    "            {\n"
    "                case 0:  ptr += 1;  break;   // UINT8\n"
    "                case 1:  ptr += 1;  break;   // INT8\n"
    "                case 7:  ptr += 1;  break;   // BOOL (int8_t)\n"
    "                case 2:  ptr += 2;  break;   // UINT16\n"
    "                case 3:  ptr += 2;  break;   // INT16\n"
    "                case 4:  ptr += 4;  break;   // UINT32\n"
    "                case 5:  ptr += 4;  break;   // INT32\n"
    "                case 6:  ptr += 4;  break;   // FLOAT32\n"
    "                case 10: ptr += 8;  break;   // UINT64\n"
    "                case 11: ptr += 8;  break;   // INT64\n"
    "                case 12: ptr += 8;  break;   // FLOAT64\n"
    "                case 8:  // STRING: uint64 length + bytes\n"
    "                {\n"
    "                    if (ptr + 8 > base + size) return false;\n"
    "                    uint64_t strLen = *reinterpret_cast<const uint64_t*>(ptr);\n"
    "                    ptr += 8;\n"
    "                    if (strLen > static_cast<uint64_t>(base + size - ptr))\n"
    "                        return false;\n"
    "                    ptr += strLen;\n"
    "                    break;\n"
    "                }\n"
    "                case 9:  // ARRAY: elem_type(int32) + count(uint64) + elements\n"
    "                {\n"
    "                    if (ptr + 4 > base + size) return false;\n"
    "                    uint32_t arrElemType = *reinterpret_cast<const uint32_t*>(ptr);\n"
    "                    ptr += 4;\n"
    "                    if (ptr + 8 > base + size) return false;\n"
    "                    uint64_t arrCount = *reinterpret_cast<const uint64_t*>(ptr);\n"
    "                    ptr += 8;\n"
    "                    for (uint64_t a = 0; a < arrCount; ++a)\n"
    "                    {\n"
    "                        switch (arrElemType)\n"
    "                        {\n"
    "                            case 0:  case 1:  case 7:\n"
    "                                if (ptr + 1 > base + size) return false; ptr += 1; break; // u8/i8/bool\n"
    "                            case 2:  case 3:\n"
    "                                if (ptr + 2 > base + size) return false; ptr += 2; break; // u16/i16\n"
    "                            case 4:  case 5:  case 6:\n"
    "                                if (ptr + 4 > base + size) return false; ptr += 4; break; // u32/i32/f32\n"
    "                            case 10: case 11: case 12:\n"
    "                                if (ptr + 8 > base + size) return false; ptr += 8; break; // u64/i64/f64\n"
    "                            case 8:  // string element: uint64 length + bytes\n"
    "                            {\n"
    "                                if (ptr + 8 > base + size) return false;\n"
    "                                uint64_t elLen = *reinterpret_cast<const uint64_t*>(ptr);\n"
    "                                ptr += 8;\n"
    "                                if (elLen > static_cast<uint64_t>(base + size - ptr))\n"
    "                                    return false;\n"
    "                                ptr += elLen;\n"
    "                                break;\n"
    "                            }\n"
    "                            default: return false;\n"
    "                        }\n"
    "                    }\n"
    "                    break;\n"
    "                }\n"
    "                default: return false;\n"
    "            }"
)

new_s, n = old_pattern.subn(new_block, s, count=1)
if n != 1:
    print(f"ERROR: pattern matched {n} times (expected 1). Aborting; file unchanged.")
    sys.exit(1)
# Restore original line endings.
if had_crlf:
    new_s = new_s.replace("\n", "\r\n")
with open(path, "wb") as f:
    f.write(new_s.encode("utf-8"))
print(f"OK: metadata value-type switch rewritten ({n} substitution). CRLF={had_crlf}")
