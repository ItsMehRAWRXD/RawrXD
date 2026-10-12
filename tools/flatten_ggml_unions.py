#!/usr/bin/env python3
"""Flatten the scale unions in the vendored ggml-common.h copy.

Why: ggml-common.h nests the super-block scales in an anonymous STRUCT inside
an anonymous UNION. MSVC promotes members of an anonymous union to the
enclosing struct, but does NOT promote members of a nested anonymous struct.
So `block.d` / `block.dmin` fail to resolve in QuantKernelRegistry_K.h,
QuantKernelRegistry.cpp and the MoE/registry kernels -- several thousand of
the remaining errors.

Fix: collapse each nested struct into the union, listing the members directly.
The union is preserved, so the packed `half2` member still overlaps the two
halves exactly as before. The static_asserts on sizeof(block_q*_K) right after
each block catch any accidental layout change at compile time.

Only touches 3rdparty/ggml/src/ggml-common.h (present here because it was
copied from the ide-closure worktree). The file is CRLF-terminated; CRLF is
preserved.
"""
import pathlib
import sys

PATH = pathlib.Path(r"F:\rawrxd\.kilo\worktrees\thorn-measure\3rdparty\ggml\src\ggml-common.h")
CRLF = "\r\n"

HEADER = CRLF.join([
    "    // FLATTENED for MSVC: an anonymous STRUCT inside an anonymous union",
    "    // does NOT have its members promoted to the enclosing struct, so",
    "    // block.d / block.dmin would not resolve. Listing them directly in",
    "    // the union does promote them, and the union is preserved so the",
    "    // half2 member still overlaps -- the layout is unchanged.",
    "    GGML_EXTENSION union {",
])

# (first-half comment, second-half comment, packed half2 member)
CELLS = [
    ("d", "dmin", "dm"),   # q2_K / q4_K / q5_K
    ("d", "m", "dm"),      # q4_1
    ("d", "m", "dm"),      # q5_1
    ("d", "s", "ds"),      # q8_1
]


def build_old(d, m, hm2):
    # Match the source formatting exactly: two spaces before each comment.
    return CRLF.join([
        "    GGML_EXTENSION union {",
        "        struct {",
        "            ggml_half %s; // delta" % d,
        "            ggml_half %s; // min" % m,
        "        } GGML_COMMON_AGGR_S;",
        "        ggml_half2 %s;" % hm2,
        "    } GGML_COMMON_AGGR_U;",
    ])


def build_new(d, m, hm2):
    return CRLF.join(HEADER + [""]).replace(
        "GGML_EXTENSION union {\n", "") [:-0] + CRLF.join([
        "        ggml_half %s;" % d,
        "        ggml_half %s;" % m,
        "        ggml_half2 %s;" % hm2,
        "    };",
    ])


def main():
    text = PATH.read_text(newline="", encoding="utf-8")
    total = 0
    for d, m, hm2 in CELLS:
        old = build_old(d, m, hm2)
        n = text.count(old)
        if n == 0:
            continue
        new = HEADER + CRLF + CRLF.join([
            "        ggml_half %s;" % d,
            "        ggml_half %s;" % m,
            "        ggml_half2 %s;" % hm2,
            "    };",
        ])
        text = text.replace(old, new)
        total += n
        print("  flattened %d block(s) with (%s, %s)" % (n, d, m))
    if total == 0:
        print("no patterns found (already flattened?)")
        return 0
    PATH.write_text(text, newline="", encoding="utf-8")
    print("flattened %d union blocks total" % total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
