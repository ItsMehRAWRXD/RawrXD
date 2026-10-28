# RECEIPT — Unlinked Symbols E2E Quintile C (011–015)

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
SYNTHETIC=0  # target; see GAPS
WORKSPACE=G:\~dev\rawrxd
```

## Prior Quintile B (verified, not rewritten)

- MagBuf join + 006/007/008 publish; 009 Mode* strip; 010 CMake-excluded
- Evidence: `RECEIPT_BATCH_006_010.md` + `BUILD_SMOKE_006_010.txt` (COMPILE_OK)
- Full Win32IDE link still NOT_RUN from B

## Ownership decisions (011–015)

| Batch | Symbols | Linked owner | Mechanism |
|-------|---------|--------------|-----------|
| 011 | AD_ProcessGGUF, SO_LoadExecFile, SO_StartDEFLATE*, SO_Print* | `rawrxd_subsystem_api.cpp` | CMake COMMENT-OMIT batch_011 (Win32IDE+RawrEngine); GOLD EXCLUDE → `streaming_orchestrator.cpp` |
| 012 | HotSwapModel, RawrXD_Native_Log, asm_spengine_cpu_optimize(void) | batch_012 | Linked RawrEngine+Win32IDE; GOLD EXCLUDE 012 |
| 013 | asm_quadbuf_init/render_thread | batch_013 → `quad_registry_*` | Shared QuadState w/ batch_001 shutdown; CMake OMIT under MASM (ASM orch/quad owners) |
| 013 | asm_orchestrator_*, gguf stage*, fnv1a | batch_013 (!MASM) / AgenticOrchestrator ASM (MASM) | Keep TU in tree |
| 014 | createOutlinePanel / createDockingPaneManager / goToLine | batch_014 headless factories using real `OutlinePanel.h` / `DockingPaneManager.h` | CMake OMIT on Win32IDE (product OutlinePanel path) |
| 015 | Sovereign_Pipeline_* + globals | batch_015 on Win32IDE | GOLD EXCLUDE 015 — `gold_link_closure.cpp` owns |

Camellia Auth ASM / Digestion_scanner.asm: **not** claimed as Mode*/SO/Sovereign owners.

## Code / CMake changes this turn

1. `src/core/quad_registry.hpp` — bind/clear/tick API; storage in batch_001
2. batch_001 — implements quad_registry + `asm_quadbuf_shutdown` → clear
3. batch_013 — drops private QuadBufState; init/render join registry
4. batch_014 — real win32app headers (no empty stub classes)
5. batch_015 — flat `extern "C"` Sovereign symbols (no nested namespace wrap)
6. CMake — Win32IDE omits 011; adds 015; GOLD FILTER EXCLUDE 013/014/015; comments align RawrEngine

## Smoke

See `BUILD_SMOKE_011_015.txt` — COMPILE_OK for 001+011–015 objects.

## Full link

```
Win32IDE_FULL_LINK=NOT_RUN
```

(Object smoke only; full link deferred as non-cheap.)

## GAPS (not PASS)

- subsystem_api Mode*/SO_* remain empty stubs (SYNTHETIC=partial) — leave until real mode ASM product-linked
- batch_011 body still defines SO/AD (reference); must stay CMake-omitted vs subsystem_api
- batch_013 product path under MASM still ASM-owned; C path exercised only in object smoke / !MASM
- batch_014 factories not wired into Win32IDE product call graph (headless/alternate only)
- Full Win32IDE / GOLD link NOT_RUN this worker
- F:\rawrxd G06 / 25-gate ledger not touched

## Next quintile (016–022)

- Audit 016–022 vs existing MagBuf / subsystem / Camellia / collab owners
- Resolve any remaining SO_/Mode dual providers (019 vs subsystem_api)
- Decide 018/020 vs batch_001 perf/shutdown ODR
- Optional: cheap Win32IDE link after 016–022 smoke if graph is small enough
- PROMOTE=0 until product open ∩ session enter ∩ tokens commit
