# RECEIPT — Unlinked Symbols E2E Quintile A (001–005)

```
PROMOTE=0
TIP_CLIMB=HOLD
SYNTHETIC=0  # target; see GAPS
WORKSPACE=G:\~dev\rawrxd
```

## Batch 001 — MagShutdown + perf

| Symbol | Owner file:function | LINKED | SYNTHETIC | Notes |
|--------|---------------------|--------|-----------|-------|
| asm_quadbuf_shutdown | unlinked_symbols_batch_001.cpp:asm_quadbuf_shutdown | 1 | 0 | Clears HWND/dims/scratch; v280 empty stubs removed |
| asm_lsp_bridge_shutdown | unlinked_symbols_batch_001.cpp:asm_lsp_bridge_shutdown | 1 | 0 | Clears cathedral LSP pointers |
| asm_gguf_loader_close | unlinked_symbols_batch_001.cpp:asm_gguf_loader_close | 1 | 0 | Calls GGUFLoader::Close via src/gguf_loader.h |
| asm_spengine_shutdown | spengine_bridge.cpp:asm_spengine_shutdown | 1 | 0 | Rolls back patch journal + VirtualProtect restore |
| asm_omega_shutdown | batch_005 (!RAWR_HAS_MASM) / omega_asm_native_kernel | 1 | 0 | Lifecycle with omega_init |
| asm_mesh_shutdown | unlinked_symbols_batch_001.cpp:asm_mesh_shutdown | 1 | 0 | Clears MagBag mesh node table |
| asm_speciator_shutdown | unlinked_symbols_batch_001.cpp:asm_speciator_shutdown | 1 | 0 | Clears MagBag genome table |
| asm_neural_shutdown | unlinked_symbols_batch_001.cpp:asm_neural_shutdown | 1 | 0 | Clears MagBag channel table |
| asm_hwsynth_shutdown | unlinked_symbols_batch_001.cpp:asm_hwsynth_shutdown | 1 | 0 | Clears MagBag LUT table |
| asm_watchdog_shutdown | unlinked_symbols_batch_001.cpp:asm_watchdog_shutdown | 1 | 0 | SecureZeroMemory region + clear |
| asm_perf_init | unlinked_symbols_batch_001.cpp:asm_perf_init | 1 | 0 | ABI: int() per perf_telemetry.hpp |
| asm_perf_begin | unlinked_symbols_batch_001.cpp:asm_perf_begin | 1 | 0 | ABI: uint64_t(uint32_t) QPC |
| asm_perf_end | unlinked_symbols_batch_001.cpp:asm_perf_end | 1 | 0 | ABI: uint64_t(uint32_t,uint64_t) |
| asm_perf_read_slot | unlinked_symbols_batch_001.cpp:asm_perf_read_slot | 1 | 0 | ABI: int(uint32_t,void*) |
| asm_perf_reset_slot | unlinked_symbols_batch_001.cpp:asm_perf_reset_slot | 1 | 0 | ABI: int(uint32_t) |

## Batch 002 — ggml / pyre

| Symbol | Owner | LINKED | SYNTHETIC | Notes |
|--------|-------|--------|-----------|-------|
| ggml_gemm_q4_0 | batch_002 | 1 (Win32IDE) | 0 | Real CPU GEMM |
| matmul_kernel_avx2 | batch_002 | 1 (Win32IDE) | 0 | Delegates to ggml path |
| asm_pyre_* | ASM if RAWRXD_HAS_ASM_PYRE else batch_002 | 1/ASM | 0 | See LAW_BATCH_002_004_ASM_OWNER.txt |
| batch_002 on RawrEngine | EXCLUDED | 0 | n/a | ASM owns pyre |

## Batch 003 — RTP + model loader

| Symbol | Owner | LINKED | SYNTHETIC | Notes |
|--------|-------|--------|-----------|-------|
| RTP_* | batch_003 | 1 | 0 | Descriptor/context blob state |
| LoadModel | batch_003 → GGUFLoader::Open/ParseHeader | 1 | 0 | Was ghost-text theater |
| ModelLoaderInit | batch_003 | 1 | 0 | Allocates GGUFLoader |
| V280_UI_* | v280_link_bridge.cpp | 1 | 0 | Removed from batch_003 (ODR) |

## Batch 004 — hotpatch / snapshot (ASM)

| Symbol | Owner | LINKED | SYNTHETIC | Notes |
|--------|-------|--------|-----------|-------|
| asm_hotpatch_* | RawrXD_Hotpatch_Kernel.asm | 1 (ASM) | 0 | batch_004.cpp EXCLUDED |
| asm_snapshot_* | RawrXD_Snapshot.asm | 1 (ASM) | 0 | batch_004.cpp EXCLUDED |
| asm_watchdog_init | win32ide_watchdog_init.cpp | 1 | partial | Minimal bool init; CRC init still gap |

## Batch 005 — watchdog status / camellia / omega

| Symbol | Owner | LINKED | SYNTHETIC | Notes |
|--------|-------|--------|-----------|-------|
| asm_watchdog_verify/get_status/get_baseline | batch_005 | 1 | 0 | ABI int returns per watchdog_service.hpp |
| asm_camellia256_auth_{en,de}crypt_file | batch_005 | 1 | partial | 2-path ABI; XOR stream until Camellia Auth ASM linked |
| asm_omega_* (!RAWR_HAS_MASM) | batch_005 | 1 | 0 | Matches omega_orchestrator.hpp |
| asm_omega_* (RAWR_HAS_MASM) | omega_asm_native_kernel.cpp | 1 | 0 | batch_005 gated out |

## Link / duplicate fixes this turn

1. Removed empty `asm_quadbuf_shutdown` / `asm_spengine_shutdown` from `v280_link_bridge.cpp` (LNK2005 risk).
2. Moved real `asm_spengine_shutdown` into `spengine_bridge.cpp` (journal rollback).
3. Aligned perf ABIs to `perf_telemetry.hpp` (uint32_t / return types).
4. Removed V280 duplicates from batch_003.
5. Did **not** link `rawrxd_*_bridge.cpp` into Win32IDE (would LNK2005 vs batch_005..008).

## GAPS (001–005) — not claimed PASS

- MagBag mesh/neural/hwsynth/speciator tables not yet published by init TUs (006–008) → shutdown clears empty tables until join.
- Camellia auth still XOR placeholder (`SYNTHETIC=partial`) until Auth ASM product-linked.
- `asm_watchdog_init` still minimal bool; CRC baseline join with MagBag incomplete.
- Full RawrXD-Win32IDE link not re-run to green in this worker (build attempted separately).
- Quadbuf init state still split (batch_013 excluded) vs shutdown in batch_001.

## Next quintile

**006–010** — mesh/speciator/neural/hwsynth init owners: join MagBag registries so batch_001 MagShutdown clears live handles; resolve batch_009–011 exclusions vs `rawrxd_subsystem_api.cpp`.
