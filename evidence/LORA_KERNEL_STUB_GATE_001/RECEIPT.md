# LORA_KERNEL_STUB_GATE_001 — RECEIPT

| Field | Value |
|-------|-------|
| ASOF_UTC | 2026-10-28T08:25:00Z |
| PROMOTE | 0 |
| TIP_CLIMB | HOLD |
| CERTIFIED | 0 |
| RELINK | NO |
| EXE_SHA_HOLD | 89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630 |
| LIVE_TETRAD | unchanged (sealed SHA; not re-run; not invented) |

## Verdict

Product-adjacent LoRA / WAL / ghost stubs were **fake-success** (`true` / `0`) but **not linked** into sealed `RawrXD-Win32IDE.exe`. Fail-closed GateMode-style (`log` + `false`/`-1`) and CMake `GATED_OMIT` so accidental link cannot claim PASS.

## Edits

| Path | Change |
|------|--------|
| `src/win32app/Win32IDE_AgenticFeatures.cpp` | LoRA init→false; WAL/ghost→-1; Camellia/SelfHost empty stubs→-1; `GateStub` |
| `src/win32app/ASM_Bridge_Implementation.cpp` | WAL/ghost panic then `-1` (was `0`) |
| `src/core/agent_wal_cli_smoke_test.cpp` | `-1` + GATED log |
| `src/core/ghost_pipeline_probe.cpp` | `-1` + GATED log |
| `src/win32app/Win32IDE_LoRAKernelBridge.h` | GATED_OMIT cite |
| `CMakeLists.txt` | omit comment under WIN32IDE_SOURCES |

## Link trace

`audit/orphan_sources.csv` + zero `CMakeLists.txt` product refs → **LINKED=0** for all named TUs. `ApplyLoRA` absent from CMake.

## Gates held

`SOURCE_WIRED != RUNTIME_REACHED`. Source fail-close ≠ runtime exercise. `PROMOTE=0`.
