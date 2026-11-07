# Batch 20 — Dispatcher containment, pagination, and smoke tests

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Verified GitHub source changes

- `84db6c15aa4f72954caa4d1264d230c44a92c9ac`: contain enumerated code.search and symbol.find files within canonical workspace, rejecting symlink escapes.
- `057697a6469bcbdf32328604a01805c06826601f`: cap audit candidate page limit and prevent offset integer overflow.
- `48e6947ac8b194e43a64cd60a8b3d849f8265a7a`: contain audit candidate source reads; reject missing source; use full-line reads and 64-bit line counters.
- `d26cb8c48b9486db8dcc13ecbf88919a89999853`: validate symbol identifier characters.
- `2055a05c6b7507bb3534c09206c6ab61560230fe`: cap candidate page offset at 100000 to avoid oversized scans.
- `6d0f9d5f3af022047f136043704c147d8270fea0`: add 15-case standalone containment smoke.
- `5e6d9ca4af62c13f80b2e2193af745b8e22368fb`: CI coverage for containment smoke and dispatcher edits.

## Actual local smoke execution

A local reconstruction of the committed C++20 workspace containment test was compiled with:
`g++ -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer`

Result: `CASE_1` through `CASE_15` all PASS, exit 0.

A local reconstruction of the prior source-search smoke was compiled with the same flags; `LONG_LINE_SEARCH=PASS`, `TOKEN_BOUNDARY=PASS`.

**Limits:** these are standalone algorithm tests reconstructed from the source, not a linked execution of the actual dispatcher, full IDE, or Windows toolchain. No GitHub Actions status or workflow run was confirmed. Source commits do not establish product certification.

## Fifteen remaining end-to-end acceptance gates

1. Windows source build
2. CTest
3. Parser protocol regression
4. Tool catalog routing
5. Model-originated tool call
6. Mutation authorization
7. editFiles disk write
8. Exact editFiles disk readback
9. ToolResult reinjection
10. Strict A→Stop→B cancellation
11. Crash recovery
12. Deep2 numerical correctness
13. GPU numerical correctness
14. GUI soak and package
15. Independent final certification

## Next priority

Build the actual Windows native IDE and agent dispatcher, run CI, and capture an authorized model-generated editFiles transaction with exact disk readback. Do not count 15 containment test cases as 15 product blockers resolved.
