# RECEIPT — INFERENCE_FLAG_AUDIT_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
REBUILD=0
VERDICT=SPLIT
WORKSPACE=G:\~dev\rawrxd
SEAL_REF=UNLINKED_SYMBOLS_E2E_001/LINK_WIN32IDE_002
SEALED_SHA256=4A5D6B31DD83CE117A1F8769D55474186C4629EA4074F033125EEE1D20F0E3CE
DATE=2026-10-28
LOCAL_ONLY=1
OLLAMA_HTTP=0
```

## Mission

Authorized audit only: map `RAWR_HAS_RAWR_INFERENCE` and `RAWRXD_LINK_INFERENCE_KERNELS_ASM` on Win32IDE; cite product generate entry points; write evidence; do not flip PROMOTE; do not claim runtime PASS; preserve sealed LINK_WIN32IDE_002 EXE.

## Verdict

**SPLIT** — inference kernel ASM is linked and `RAWRXD_LINK_INFERENCE_KERNELS_ASM=1`, while the product-facing compile define `RAWR_HAS_RAWR_INFERENCE=0` is hard-set for `RawrXD-Win32IDE`. Product Open/Run/generate does **not** consult that flag (path bypasses it). Not DISABLED, not MISREPORTED for kernel UI, not a PROMOTE-adjacent flip.

## Key cites

| Item | Cite |
|------|------|
| Hard-set product flag | `CMakeLists.txt:7618` `RAWR_HAS_RAWR_INFERENCE=0` |
| Sibling sovereign flag | `CMakeLists.txt:7617` `RAWR_HAS_SOVEREIGN_ENGINES=0` |
| ASM feature pack (kernels=1 iff MASM) | `CMakeLists.txt:2103` |
| Pack applied to Win32IDE | `CMakeLists.txt:7622` |
| Sealed cl DEFINES | `build_win32ide_link001/build.ninja` → `-DRAWR_HAS_RAWR_INFERENCE=0` `-DRAWRXD_LINK_INFERENCE_KERNELS_ASM=1` |
| Only `#if` consumer of product flag | `src/runtime_core.cpp:27-28,65-66` (`register_rawr_inference`) |
| Kernel ASM in Win32IDE link set | `CMakeLists.txt:1997` + `7493-7505` (not removed) |
| Kernel extern ifdef | `streaming_engine_registry.cpp:43-47` |
| Kernel UI registration (always) | `streaming_engine_registry.cpp:193,362-380` |
| UX surfaces registry | `Win32IDE_StreamingUX.cpp:531-592` |
| Map: ASM symbols linked | `matmul_f16_avx512_masm` / `rmsnorm_avx512_masm` ← `inference_kernels.asm.obj` |
| Product open | `product_deep2_infer.cpp:36` / `ProductRuntime.hpp:56` |
| Product generate | `ProductRun.hpp` → `ProductRunDecode.hpp` → `Deep2Engine::generateStream` |
| Promote gate (held) | `Deep2ProductGate.hpp::PromoteReady` — not exercised |

## Scope notes

- `deep2/`, `agentic/`, `inference/` (sources), `win32app/`: no `#if RAWR_HAS_RAWR_INFERENCE`.
- Standalone `RawrXD-InferenceEngine` sets `RAWRXD_LINK_INFERENCE_KERNELS_ASM=1` separately (`src/inference/CMakeLists.txt:110`); out of Win32IDE product seal.
- No `option()` found for `RAWR_HAS_RAWR_INFERENCE` — Win32IDE value is a one-line literal.

## Recommended next flip (not applied)

```
FLIP: CMakeLists.txt:7618  RAWR_HAS_RAWR_INFERENCE=0 → 1
STATUS: HOLD (APPLY=0)
WHY_NOT_NOW: Does not gate ProductOpenSession / ProductRun / generateStream.
             Only re-arms legacy init_runtime→register_rawr_inference.
             Stub owner exists (rawr_engine.cpp:227-229); not proven product-correct.
NEXT: Runtime exercise of sealed EXE product path; keep PROMOTE=0.
```

## Fail-closed

```
LINK=OK (prior seal) ≠ RUNTIME_REACHED ≠ TOKEN_SURVIVED ≠ PERFORMANCE_PASS
NOT_RUN != PASS
CERTIFIED=0 · PROMOTE=0 · TIP_CLIMB=HOLD
No CMake flip applied. No EXE rebuild. No Camellia/Mode/tetrad work.
```

Machine twin: `LAW.txt` in this directory.
