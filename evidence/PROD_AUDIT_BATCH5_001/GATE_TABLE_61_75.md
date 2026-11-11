# Batch 5 — Gates 61–75 disposition (CI/release/shipping)

```
AUDIT_ID=PROD_AUDIT_BATCH5_001
DATE=2026-11-03
PROMOTE=0
REBUILD_AUTHORITY=0
SEAL_CB34EF4E_UNTOUCHED=1
FULL_PRODUCT_E2E_CERTIFIED=0
```

| # | Requirement | Status | Exact next action |
|---|-------------|--------|-------------------|
| 61 | Real LSP JSON-RPC lifecycle | Unverified | Wire non-Qt LSP process (or prove Native path) and exercise initialize→initialized→shutdown against clangd; Qt `lsp_client.cpp` alone does not close Native. |
| 62 | Debugger with real debuggee | Held (Partial UI) | Replace simulated eval (`Win32IDE_Debugger.cpp:758`) and flag-only attach (`:282`) with real `DEBUG_PROCESS` debuggee; prove breakpoint+locals on Native EXE. |
| 63 | Embedded browser isolation | Unverified | Locate/implement WebView2 (or deny feature); run isolation smoke on Native. No Win32IDE WebView symbols found. |
| 64 | Native compiler frontends | Unverified | Exercise product compiler frontend path (ml64/cl admission) end-to-end from IDE/toolchain owner; emit receipt. |
| 65 | Native linker/platform outputs | Unverified | Produce PE/COFF via product linker path (`src/toolchain/linker`) and verify platform output on clean machine. |
| 66 | One authoritative no-Qt build graph | Blocked | Declare `RawrXD-Win32IDE-Native` as sole shipping IDE; quarantine `RawrXD-ModelLoader` + duplicate win32app/ModelLoader trees from authority claims. |
| 67 | WIP/source manifest reconciliation | Partial | Diff tip vs sealed WIP/manifest; close open deltas without rebuild authority. |
| 68 | Clean checkout release build | Unverified | After Gate 69 runners recover: clean clone → cmake nodeps → `--target RawrXD-Win32IDE-Native` → hash receipt. |
| 69 | CI runner and job execution | FAIL | Fix Actions runner allocation (`runner_id≠0`, `steps≠[]`); then re-run Native + Security. See `CI_RUNNER_ZERO_RECEIPT.md`. |
| 70 | Unit/regression/headless E2E | Partial | Preserve prior local CTest/component receipts; re-bind to post-runner CI + same Native SHA. |
| 71 | Security/sandbox certification | Unverified | Security Suite never executed steps; re-run after Gate 69; add sandbox policy witness. |
| 72 | AMD host stability and crash capture | Blocked | Independent host-stability evidence required; prior GPU/host blockers remain open. |
| 73 | Reproducible offline packaging | Unverified | Offline package script + content hash on clean checkout after Gate 68. |
| 74 | Full autonomous product acceptance | Unverified | Blocked on Batches 1–4 product E2E + CI restore; Self-Release still requires native agent (YAML fails on missing `RawrXD-Agent.exe`). |
| 75 | Production certification/promotion | Held | `PROMOTE=0` until PromoteReady conjunction; do not replace seal `CB34EF4E`. |

## Batch exit (still open)

Clean checkout reproduce + real CI execution + safety/stability + verifiable package + full autonomous scenario — **none closed this audit**.
