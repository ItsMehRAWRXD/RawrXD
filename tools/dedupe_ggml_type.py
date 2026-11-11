#!/usr/bin/env python3
"""Replace the duplicate Deep2::GGMLType enum in GGUFLoader.hpp with an include
of the canonical QuantTypeTable.hpp definition.

Both headers declared `namespace Deep2 { enum class GGMLType ... }`. When a TU
includes both (QuantKernelRegistry.cpp does, via QuantKernelRegistry.hpp and
GGUFLoader.hpp), the duplicate definition is a hard error, which is what
produced the ~1100 "use of undefined type 'Deep2::GGMLType'" diagnostics.

QuantTypeTable.hpp is self-contained (<cstdio> only), sits in the same
src/deep2 directory, and carries static_asserts pinning every id to ggml"s
ggml_type numbering -- so it is the authoritative definition. GGUFLoader.hpp
now includes it instead of redefining it, which keeps every TU on one
definition and leaves GGUFLoader.hpp"s own public surface (GGUFMetaType,
GGUFTensor, ...) untouched.
"""
import pathlib

PATH = pathlib.Path(r"F:\rawrxd\.kilo\worktrees\thorn-measure\src\deep2\GGUFLoader.hpp")

OLD_START = "namespace Deep2 {\n\n// GGMLType is defined once"
# Find the enum block to remove: from the `enum class GGMLType` line through
# the first `};` that closes it.
OLD_ENUM_START = "namespace Deep2 {"
OLD_ENUM_END = "enum class GGUFMetaType : uint32_t {"


def main():
    lines = PATH.read_text(encoding="utf-8").split("\n")
    # Locate the enum class GGMLType block.
    start = None
    for i, ln in enumerate(lines):
        if ln.strip() == "enum class GGMLType : uint32_t {":
            start = i
            break
    if start is None:
        print("enum class GGMLType not found; nothing to do")
        return 1
    end = None
    for j in range(start, len(lines)):
        if lines[j].strip() == "};":
            end = j
            break
    if end is None:
        print("could not find the end of the enum; nothing to do")
        return 1
    # Walk back to the `namespace Deep2 {` that owns it (usually the line above
    # the comment block).
    owner = start
    for k in range(start - 1, -1, -1):
        if lines[k].strip() == "namespace Deep2 {":
            owner = k
            break

    replacement = [
        "namespace Deep2 {",
        "",
        "// GGMLType is defined once, canonically, by QuantTypeTable.hpp, which",
        "// carries compile-time static_asserts pinning every id to ggml's",
        "// ggml_type numbering. It used to be redefined here; when a TU includes",
        "// both headers (QuantKernelRegistry.cpp does, via QuantKernelRegistry.hpp",
        "// and GGUFLoader.hpp) that duplicate definition is a hard error, which",
        "// is what produced the \"use of undefined type 'Deep2::GGMLType'\"",
        "// diagnostics. QuantTypeTable.hpp is self-contained (<cstdio> only) and",
        "// lives in this same directory, so including it costs nothing.",
        '#include "QuantTypeTable.hpp"  // IWYU pragma: export',
        "",
    ]
    new_lines = lines[:owner] + replacement + lines[end + 1:]
    PATH.write_text("\n".join(new_lines), encoding="utf-8")
    print("replaced lines %d..%d with an include of QuantTypeTable.hpp"
          % (owner + 1, end + 1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
