# Batch 3 — Agent Runtime / Tool Authority Audit

Date: 2026-11-05
Branch: fix/deep2-multimodel-safety-20261025
Disposition: SOURCE_FIXES_COMMITTED; RUNTIME_VERIFICATION_PENDING
Promotion: HELD

## Source-backed findings and changes

1. `~dev/rawrxd/src/deep2/AgentToolRegistry.hpp`: duplicate aliases *within the same registration* were not detected after canonicalization, since the existing duplicate check only consulted already-registered aliases. Added an in-flight alias-list duplicate check. Commit `98466371c021de305795e10f129706321546182d`.
2. `~dev/src/rawr_agent_dispatch.cpp`: `toolFileRead` previously blocked a literal `..` substring but joined the untrusted path to workspace root without canonical containment. Absolute paths and symlink targets could escape the workspace. Added absolute-path rejection and canonical path-component containment. Commit `8bac28d089b8a028b8d4450ef988197c3c0ed0fc`.

## Fifteen verification cases for the next portable test run

| ID | Test | Expected |
|---|---|---|
| A01 | Register unique tool ID | PASS |
| A02 | Register distinct aliases | PASS |
| A03 | Register same alias twice | REJECT |
| A04 | Register equivalent dotted/dashed aliases | REJECT |
| A05 | Register alias already used by another tool | REJECT |
| A06 | Unregister tool and reuse alias | PASS |
| A07 | Read ordinary file under workspace | PASS |
| A08 | Read nested file under workspace | PASS |
| A09 | Read absolute external path | REJECT |
| A10 | Read relative `../` escape | REJECT |
| A11 | Read sibling path with same textual prefix | REJECT |
| A12 | Read symlink targeting outside workspace | REJECT |
| A13 | Read symlink targeting inside workspace | PASS |
| A14 | Read workspace root as file | REJECT |
| A15 | Read nonexistent file | ERROR, no unauthorized access |

The matrix is **not** a test receipt. All fifteen cases are PENDING until compiled and executed on the actual code. Symlink creation privileges and filesystem semantics may vary by host.

## Remaining broader product gates

Model-originated editFiles, disk persistence, same-model tool-result continuation, Deep2 numeric correctness, native GPU inference, IDE integration, soak/stress, reproducible Windows package, and final certification remain OPEN or NOT_VERIFIED. Do not infer PASS from source review.

## Evidence policy

Record test command, toolchain, exact source commit, stdout/stderr, exit code, and artifact SHA. Any absent or failing evidence must block promotion.
