# RawrXD End-to-End: 15-Blocker Verification Register

ASOF_UTC=2026-11-05
SOURCE_BRANCH=fix/deep2-multimodel-safety-20261025
CERTIFIED=0
PROMOTE=0
VERDICT=NOT_VERIFIED

This register is a fail-closed audit checklist, **not** a PASS receipt. GitHub source inspection alone cannot validate native Windows GUI behavior, MSVC builds, local models, GPU correctness, or a packaged executable. Do not promote based on this file.

## Required gates

| ID | Gate | Current disposition | PASS evidence required |
|---|---|---|---|
| 01 | T05 strict cancellation | REVERIFY | SHA-bound A→Stop→B request/cancel/late-response receipts on current candidate; historical B544 PASS is not transferable |
| 02 | Model-originated tool call | OPEN | Trace model-emitted editFiles payload and parser without synthetic injection |
| 03 | Agent edit disk persistence | OPEN | Approved edit, exact marker readback, before/after file SHA |
| 04 | Tool result reinjection | OPEN | Real ToolResult, same session continuation and subsequent model tokens |
| 05 | Deep2 numeric correctness | OPEN | Layer-12 abort resolved; finite-value checks and CPU/GPU golden output comparison |
| 06 | Native GPU inference | OPEN | Actual GGUF load, token stream, and IDE display on selected GPU |
| 07 | T10 recovery | REVERIFY | Unsaved edits, tabs, restart and disk/session readback on candidate |
| 08 | T18 soak | OPEN | Long-running run with crash, handle, heap, and GPU resource accounting |
| 09 | T19 stress | OPEN | Repeated Stop/Send/model switching, no stale response rendered |
| 10 | Tool Authority boundaries | OPEN | Traversal, symlink, denial, approval, timeout, cancellation and command-policy tests |
| 11 | IDE integration | OPEN | Native explorer/editor/chat/build/test/terminal/settings and tool history physical smoke |
| 12 | Multi-agent execution | OPEN | Independent contexts, delegation, critique, revision, shared authority receipts |
| 13 | Reproducible clean build | OPEN | Fresh checkout, pinned toolchain, configure/build/CTest logs and artifact SHA |
| 14 | T24 packaging | OPEN | Extracted package dependency/hash checks and independent launch smoke |
| 15 | T25 certification | BLOCKED | All preceding applicable gates PASS on the same release SHA; independent review |

## Evidence integrity rules

1. Record branch HEAD, build configuration, compiler/SDK, test host, candidate SHA-256 and UTC timestamps.
2. Every PASS must link to raw logs and machine-checkable receipts. Missing receipts mean NOT_VERIFIED, never PASS.
3. Never overwrite frozen B544 or other sealed binaries. Repair in a new candidate and re-run affected tests.
4. Distinguish harness faults from product faults; do not assign product root cause from crash signature alone.
5. Preserve local-only inference and explicit authorization for file mutations.
6. T25 remains blocked until package hashes and all required receipts refer to the same candidate.

## Source references

- evidence/POST_E59D_CANDIDATE_001/FINISH_25_BACKLOG.md (historical Nov 3 baseline: 16/25, 9 unresolved)
- GitHub issues #42, #44, #45, #46, #47, #50 (broader certification ladder)
- Commit 1657ce73504ae3402fbb2cb03ef0ab936b2ae6b7 (T05 request lifecycle logging; does not itself prove runtime PASS)

## Next execution order

Confirm latest branch HEAD and B544 receipts; isolate a new candidate; prove model tool call → authorized disk edit → ToolResult → same-model continuation; fix Deep2 numeric fault; then GUI, soak, stress, clean build, package, and independent certification.
