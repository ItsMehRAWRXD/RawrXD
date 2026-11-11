# LANG_DEBUG_GAP_MATRIX — Batch 21 prep (READ-ONLY)

```
AUDIT=UPPER_TIER_MASTER_001/BATCH_21_AUDIT/LANG_DEBUG_GAP_MATRIX
ASOF_UTC=2026-11-11T17:45:00Z
PRIMARY=F:\rawrxd
CROSS_CHECK=G:\~dev\rawrxd
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
SOURCE_WIRED != RUNTIME_REACHED
NOT_RUN != PASS
NO_INVENT_PASS=1
NO_SOURCE_EDITS=1
NO_BUILD_WIN32IDE=1
SUCCESSOR_OF=4f6b99c7-f414-4f3c-a0ae-1da6026017d4
```

Read-only inventory for Upper-Tier Batch 21 language/debug prep (LSP runtime, navigation, refactor, diagnostics, DAP). No product code edits. No `build_win32ide` (Batch17 sole owner `63513ece`). All runtime cells this audit: **NOT_RUN**.

## Hard blocker

| Field | Value |
|-------|-------|
| ID | `BATCH17_G1_NO_LINKED_NATIVE_EXE` |
| Exe | `F:\rawrxd\build_win32ide\Release\RawrXD-Win32IDE-Native.exe` |
| Present | **false** |
| Cite | `AGENT_RUNTIME_VALIDATION_001/DISPOSITION.json` (G1=FAIL); `BATCH_17/G1_HANDOFF.txt` |

Product-path LSP/DAP acceptance is blocked until Batch17 links Native.

## Tree delta (F vs G)

| Surface | F:\rawrxd | G:\~dev\rawrxd |
|---------|-----------|----------------|
| `Win32IDE_LSPClient` / `LSPServer` / Semantic / Hover / Rename / CodeCompletion / GoTo / Refs | In native CMake | Broader + AsmSemantic |
| `Win32IDE_PeekOverlay.cpp` | **On disk, NOT in F CMake** | In CMake (+ `PeekView`) |
| `Win32IDE_DAPServer` + `DebuggerIntegration` + `BreakpointManagerPanel` | In native CMake | Present |
| `Win32NativeDebugBackend` | In F CMake | Absent under G win32app |
| `DAPIntegrationBridge` / `Win32IDE_DapAdapterSpawn` / `Win32IDE_DapServiceProduct` | **Absent** | On disk; **not** tip-CMake members (candidate wire COMPLETION_007/017) |
| `Win32IDE_NativeDebugPanel` | Absent | In G CMake |
| `Win32IDE_LSPServer_stubs.cpp` | On disk, **not** in CMake | Absent |

F is Batch21 authority for the linked native LSP + DAPServer surface, except the PeekOverlay CMake gap. G DAP product-bridge TUs are candidate-only evidence — do not invent tip CMake membership.

## Capability matrix

| capability | path (authority) | source_wired | runtime_reached | gaps (short) |
|------------|------------------|-------------:|----------------:|--------------|
| lsp_completion | `Win32IDE_LSPClient.cpp` `lspCompletion`; `Win32IDE_CodeCompletion.cpp` | 1 | 0 | JSON-RPC + hybrid popup SOURCE_WIRED; needs running LS; no live E2E; probe_lsp historically failed compile |
| lsp_hover | `lspHover` / `Win32IDE_HoverTooltips.cpp` | 1 | 0 | Tooltip path wired; no tip Native exe to exercise |
| lsp_goto_definition | `lspGotoDefinition` → `showPeekOverlayWithItems`; `GoToSymbol` | 1 | 0 | Depends on PeekOverlay; F CMake omits PeekOverlay TU |
| lsp_find_references | `lspFindReferences`; `ReferencesPanel` | 1 | 0 | Panel wired; peek overlay same F CMake gap; SemFindRefs parallel uncertified |
| lsp_rename | `lspRenameSymbol` / `applyWorkspaceEdit`; `RenamePreview` | 1 | 0 | WorkspaceEdit apply SOURCE_WIRED; multi-file rename E2E NOT_RUN |
| lsp_semantic_tokens | `SemanticTokens` / `SemanticPanel` / `SemanticIndex` | 1 | 0 | Request/parse SOURCE_WIRED; live highlight unproven; G AsmSemantic absent on F |
| lsp_diagnostics | `publishDiagnostics`; `LSPServer`; `problems_aggregator` | 1 | 0 | Handler + publish SOURCE_WIRED; stubs not in CMake; squiggle/panel E2E NOT_RUN |
| lsp_peek | `Win32IDE_PeekOverlay.cpp` (disk); G PeekView | **0** | 0 | F CMake ABSENT PeekOverlay; goto/refs call overlay APIs; G1 peek still OPEN |
| dap_launch | `DAPServer::handleLaunch` → `startDebugging`; NativeDebugBackend | 1 | 0 | Always success response invent-thin risk; prior SESSION_REAL ≠ tip Batch17 SHA |
| dap_attach | `handleAttach` | 1 | 0 | Calls `startDebugging`, not `DebugActiveProcess`; prior receipt `DebugActiveProcess_IN_EXE=0` |
| dap_breakpoints | `handleSetBreakpoints`; BreakpointManagerPanel | 1 | 0 | `verified=true` unconditional; prior `DEBUG_BP_HIT_EVIDENCE=0`; BP followon survival FAIL |
| dap_step_continue | continue/next/stepIn/stepOut + Native backend | 1 | 0 | Fail-closed when inactive; prior candidate step/continue ≠ tip CERTIFIED |
| dap_variables_scopes_stack | handleVariables/Scopes/StackTrace; DebugWatchFormat | 1 | 0 | Variables empty even when active; idle stack synthetic; watch demo ≠ DAP var PASS |

**Counts:** capabilities=13 · source_wired=12 · source_wired_0=1 (peek) · runtime_reached=0 · CERTIFIED=0 · PROMOTE=0

## Claims vs reality

| Claim / surface | Reality (this inventory) |
|-----------------|--------------------------|
| LSP completion/hover/goto/refs/rename/semantic/diagnostics “wired” | SOURCE_WIRED on F CMake TUs; **runtime_reached=0** (no Native exe). |
| Peek / definition overlay | Call sites exist; **F PeekOverlay not CMake-linked** → product path incomplete (`source_wired=0`). |
| DAP launch success | `handleLaunch` always `sendResponse(true)` + “Program launched via DAP” — invent-thin if parent thin. |
| DAP attach | `processId` → `startDebugging()` masquerade — not true attach. |
| DAP breakpoints verified | Unconditional `verified=true`; no tip BP-hit E2E. |
| DAP variables | Empty array even when `isDebugActive`. |
| Prior `SESSION_REAL=1` debug probe | Candidate `build_tip_ext_host_001` SHA; `PRODUCT_PASS=0` `PROMOTE=0`; **≠** tip `build_win32ide`. |
| G DAPIntegrationBridge / DapAdapterSpawn / DapServiceProduct | On-disk G + sealed candidate receipts; **not** tip CMake; absent on F. |

## Prior sealed evidence (cited, not re-run)

- `F:\rawrxd\evidence\AGENT_RUNTIME_VALIDATION_001\DISPOSITION.json` — G1 FAIL; orch RUNTIME_REACHED 0/4
- `F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_17\G1_HANDOFF.txt` — LSPServer restored; peek in Batch17 ask; CERTIFIED=0
- `F:\rawrxd\evidence\PROD_AUDIT_BATCH5_001\DEBUGGER_LSP_FILELINE.md` — historical Qt/Native file-line audit
- `F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\debug_probe_ec811_bind\DEBUG_SESSION_REAL_TIP002_RECEIPT.txt` — SESSION_REAL=1; BP_HIT=0; DebugActiveProcess_IN_EXE=0; PRODUCT_PASS=0
- `G:\~dev\rawrxd\evidence\WIN32IDE_CONTINUOUS_COMPLETION_017\DAP_BRIDGE_PRODUCT_WIRE_001\RECEIPT.md` — INVENT_DAP_PASS=0
- `G:\~dev\rawrxd\evidence\WIN32IDE_CONTINUOUS_COMPLETION_007\COMMAND_PALETTE_DAP_SPAWN_PRODUCT_WIRE_001\RECEIPT.md` — INVENT_DAP_PASS=0
- `G:\~dev\rawrxd\evidence\BREAKPOINT_FOLLOWON_REPROVE_5BB7_001\SUMMARY.txt` — RUNTIME_SURVIVAL_PASS=0

## Batch 21 prep blockers

1. Native exe absent under `build_win32ide\Release` (Batch17 G1).
2. F `PeekOverlay.cpp` not in native CMake — peek/goto/refs overlay incomplete vs G.
3. DAP attach masquerade; empty variables; invent-thin idle stack / unconditional BP verified.
4. G DAP product-bridge TUs not on F and not tip-CMake on G.
5. Do not promote prior candidate SESSION_REAL / BP SOURCE_WIRED to tip CERTIFIED.
6. All runtime cells this audit: **NOT_RUN** (≠ PASS).

## Next executable gates (explicitly NOT_RUN here)

1. Batch17 sole-owner clean link of `RawrXD-Win32IDE-Native.exe`
2. Add/confirm `PeekOverlay.cpp` in F `RAWRXD_NATIVE` then smoke peek/goto/refs
3. LSP E2E: start server → completion/hover/goto/refs/rename/semantic/diagnostics with live JSON-RPC
4. DAP E2E: launch → setBreakpoints → BP hit → step/continue → real variables/scopes/stack; true `DebugActiveProcess` attach or hold OPEN
5. Decide F absorb of G DAPIntegrationBridge vs F DAPServer+NativeDebugBackend-only; decide tip-CMake membership for G DAP product TUs

Machine-readable twin: `LANG_DEBUG_GAP_MATRIX.json`
