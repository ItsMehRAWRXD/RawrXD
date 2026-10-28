# RECEIPT — Unlinked Symbols E2E Quintile D+E (016–022)

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
LINK=NOT_RUN
WORKSPACE=G:\~dev\rawrxd
DATE=2026-10-28
```

## Prior Quintile C (verified, not rewritten)

- Evidence: `RECEIPT_BATCH_011_015.md` + `BUILD_SMOKE_011_015.txt` (COMPILE_OK)
- Full Win32IDE link still NOT_RUN from C

## Ownership table (016–022)

| Batch | Symbols / role | Linked owner | CMake disposition |
|-------|----------------|--------------|-------------------|
| 016 | `g_AgentRegistry[32]` + `RawrXD_Sentinel_CalculateHash_MASM` | Win32IDE: `unlinked_symbols_batch_016.cpp`; GOLD: `gold_link_closure.cpp` | RawrEngine OMIT; Win32IDE INCLUDE; GOLD FILTER EXCLUDE |
| 017 | Titan_*/Sampler_*/NLShell_ValidateCommand C fallback | Object-smoke / GOLD-if-needed; prefer ASM | RawrEngine+Win32IDE OMIT |
| 018 | AgentOllamaClient; `asm_gguf_loader_close` / `asm_lsp_bridge_shutdown` | `AgentOllamaClient.cpp`; MagBuf `batch_001` | **OMIT** RawrEngine+Win32IDE+GOLD (REFERENCE TU empty) |
| 019 | AD/SO; Camellia auth; watchdog; `find_pattern_asm` | `rawrxd_subsystem_api.cpp`; `batch_005`; watchdog MagBuf; `byte_level_hotpatcher.cpp` | **OMIT** RawrEngine+Win32IDE+GOLD (REFERENCE TU empty) |
| 020 | `asm_perf_*` slot API (`perf_telemetry.hpp` ABI) | MagBuf `batch_001` | **OMIT** RawrEngine+Win32IDE+GOLD (REFERENCE TU empty) |
| 021 | SetCompletionBackendNative / AgentCoordinator C / BraidedLoader_* | `unlinked_symbols_batch_021.cpp` | Win32IDE INCLUDE; AnnotationOverlay → real TU |
| 022 | Deep2APIServer + Production + VAL038 C fallbacks | `unlinked_symbols_batch_022.cpp` | Win32IDE INCLUDE; RawrEngine OMIT; Profiler/etc stripped to product TUs |

Camellia Auth ASM / Digestion_scanner.asm: **not** claimed as Mode*/SO/Sovereign owners.
No new mag/quad registries; no new platform macros.

## Omit confirmation (018 / 019 / 020)

```
018_OMIT_RawrEngine=YES
018_OMIT_Win32IDE=YES
019_OMIT_RawrEngine=YES
019_OMIT_Win32IDE=YES
020_OMIT_RawrEngine=YES
020_OMIT_Win32IDE=YES
```

`asm_gguf_loader_close` and `asm_perf_*` clashes were **isolated by CMake COMMENT-OMIT of 018/020 before object smoke**.
018/020 source bodies are reference anchors only; MagBuf `batch_001` remains sole C provider of those symbols on product lanes.

## Smoke

See `BUILD_SMOKE_016_022.txt`:

| TU | EXIT |
|----|------|
| 016 | 0 |
| 017 | 0 |
| 018 | 0 |
| 019 | 0 |
| 020 | 0 |
| 021 | 0 |
| 022 | 0 |

`FAILS=0` · `BAT_EXIT=0` · aggregate COMPILE_OK for objects only.

## Full link

```
Win32IDE_FULL_LINK=NOT_RUN
```

(User authorization required; not executed this worker.)

## Law artifact

`LAW_BATCH_016_022_OWNER.txt` — ownership locked; PROMOTE=0.

## GAPS (not PASS)

- Object smoke ≠ link; LINK=NOT_RUN
- 017 Titan C path SYNTHETIC=partial (scalar ≠ AVX512 product)
- 022 Deep2APIServer/Production method bodies SYNTHETIC=partial
- Camellia auth remains SYNTHETIC=partial until product ASM
- CERTIFIED=0 · PROMOTE=0 · TIP_CLIMB=HOLD
