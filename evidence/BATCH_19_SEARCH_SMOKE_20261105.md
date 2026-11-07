# Batch 19 — Agent source search repairs and local algorithm smoke

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0

## Product defects fixed in agent dispatcher

1. `code.search` read source through a fixed 16,384-byte buffer. Long lines were truncated and stream failbit could prevent further scanning. Replaced with `std::getline(std::string)` and 64-bit line counters.
2. `symbol.find` and `symbol.references` used the same fixed buffer, truncating long lines. Replaced with `std::getline`.
3. Symbol matching checked only the first substring occurrence on each line. Now checks all occurrences.
4. Identifier-boundary detection considered only alphanumeric characters, treating underscore as a separator. Now considers underscores part of identifiers.
5. `max_hits` accepted up to UINT32_MAX, potentially producing excessive results. Both search tools now clamp to 200 hits.

## Commits

- `ad70dfc560af76f4bb521f1891731e55c20ab13d`: full-line code.search.
- `38fffaeaedeb20d4ca9692a2d03c30af6ce9874d`: full-line symbol search and token-boundary scan.
- `b8dea94d302743e22ed62966643d7bcb16e84866`: add standalone source-search smoke.
- `90e0fb2cdc443cb4924e8d3bdd09b83365f9d6e1`: correct C++ newline escapes in fixture.
- `7cc03a635d09a010b796ef693c96fe43b4bb90ed`: wire smoke into Linux CI.
- `a5504db38324e592c855a239a27556df5d285fc5`: include cstdint.
- `d0ad5d7bc8058e7e94df321894d8ca7b8e9ac2c7`: clamp max_hits to 200.

## Local smoke executed in isolated Linux container

Built and ran an independently compiled C++20 smoke harness reproducing the corrected full-line and token-boundary algorithms with `g++ -std=c++20 -Wall -Wextra -Werror`.

Output:
```
LONG_LINE_SEARCH=PASS
TOKEN_BOUNDARY=PASS
```

**Scope limitation:** This local test exercised a standalone algorithm implementation, not the exact GitHub-committed test binary, full dispatcher, native Windows IDE, or model runtime. GitHub returned no commit status checks or workflow runs for latest source commit.

## Remaining end-to-end obligations

15-gate native certification checklist remains OPEN. Prioritize real model-originated authorized file edit, disk readback, ToolResult reinjection, Windows build/CTest, Deep2 numerical correctness, GPU, soak, packaging and independent certification. Do not count the five dispatcher defects as 15 closed gates.
