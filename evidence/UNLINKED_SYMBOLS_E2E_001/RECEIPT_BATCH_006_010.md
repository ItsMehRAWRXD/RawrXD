# RECEIPT — Unlinked Symbols E2E Quintile B (006–010)

```
PROMOTE=0
TIP_CLIMB=HOLD
SYNTHETIC=0  # target; see GAPS
WORKSPACE=G:\~dev\rawrxd
```

## MagBag join (closes 001–005 gap)

| Init | Owner TU | Publishes | Cleared by |
|------|----------|-----------|------------|
| asm_mesh_init | batch_006 | mag_publish_mesh_node | asm_mesh_shutdown (batch_001) |
| asm_speciator_init | batch_007 | mag_publish_speciator_genome | asm_speciator_shutdown |
| asm_neural_init | batch_008 | mag_publish_neural_channel | asm_neural_shutdown |
| asm_hwsynth_init | batch_008 | mag_publish_hwsynth_lut | asm_hwsynth_shutdown |

API: `src/core/mag_registry.hpp` · impl in batch_001. Epoch-aware republish after MagShutdown free.

## Batch 006 — Omega (!MASM) + mesh

| Symbol | Owner | LINKED | SYNTHETIC | Notes |
|--------|-------|--------|-----------|-------|
| asm_omega_world_model_update / agent_spawn / agent_step / execute_pipeline / get_stats | batch_006 when !RAWR_HAS_MASM; else omega_asm_native_kernel | 1 | 0 | Cathedral int ABI; gated to avoid LNK2005 under MASM |
| asm_mesh_init + topology/dht/shard/gossip/quorum/crdt_merge | batch_006 | 1 | 0 | Mag publish; Digestion_scanner.asm not linked |

## Batch 007 — mesh cont + speciator

| Symbol | Owner | LINKED | SYNTHETIC | Notes |
|--------|-------|--------|-----------|-------|
| asm_mesh_crdt_delta / fedavg / zkp_* / get_stats | batch_007 | 1 | 0 | |
| asm_speciator_init + genome/mutate/crossover/evaluate/select/speciate/compete/migrate/gen_variant | batch_007 | 1 | 0 | Mag publish on init |

## Batch 008 — neural + hwsynth init

| Symbol | Owner | LINKED | SYNTHETIC | Notes |
|--------|-------|--------|-----------|-------|
| asm_speciator_get_stats | batch_008 | 1 | partial | Counters borrowed from neural/hwsynth locals |
| asm_neural_* | batch_008 | 1 | 0 | Mag channel publish |
| asm_hwsynth_init / gen_gemm_spec | batch_008 | 1 | 0 | Mag LUT publish |

## Batch 009 — hwsynth continued (Mode* stripped)

| Symbol | Owner | LINKED | SYNTHETIC | Notes |
|--------|-------|--------|-----------|-------|
| asm_hwsynth_analyze_memhier / profile_dataflow / est_resources / predict_perf / gen_jtag_header / get_stats | batch_009 | 1 (RawrEngine+Win32IDE) | 0 | Re-enabled on RawrEngine after Mode* strip |
| InjectMode..BasicBlockCovMode | rawrxd_subsystem_api.cpp | 1 | partial | Empty stubs; see LAW |

## Batch 010 — EXCLUDED

| Symbol | Owner | LINKED | SYNTHETIC | Notes |
|--------|-------|--------|-----------|-------|
| StubGenMode..AVScanMode | rawrxd_subsystem_api.cpp | 1 | partial | Empty stubs |
| SO_InitializeVulkan / Streaming / Arena / ThreadPool / Pipelines / PrefetchQueue | rawrxd_subsystem_api.cpp | 1 | partial | int ABI; GOLD may use streaming_orchestrator.cpp |
| batch_010.cpp | reference only (#if 0) | 0 | n/a | CMake EXCLUDED Win32IDE+RawrEngine |

## Link / ODR fixes this turn

1. MagBag publish API + free-on-shutdown in batch_001.
2. Omega continued symbols ABI-aligned + `#if !RAWR_HAS_MASM` (no ODR vs omega_asm_native_kernel).
3. Mode* removed from batch_009; 010 emptied/excluded (LAW_BATCH_009_010_OWNER.txt).
4. CMake: RawrEngine includes 009; Win32IDE excludes 010.

## GAPS (006–010) — not claimed PASS

- Mode*/SO_* in subsystem_api remain empty stubs (SYNTHETIC=partial) until real ASM modes product-linked.
- Cathedral mesh/neural/speciator/hwsynth headers under RAWR_HAS_MASM still declare richer ABIs than C fallbacks — call sites that assume full MASM ABI need ASM objs (Digestion_scanner.asm excluded).
- Full RawrXD-Win32IDE link NOT_RUN this worker.
- F:\rawrxd Kimi numerical ledger not touched.

## Smoke

See `BUILD_SMOKE_006_010.txt` — COMPILE_OK for 001+006–010.

## Next quintile

**011–015** — resolve batch_011 vs subsystem_api (AD_ProcessGGUF / SO_LoadExecFile); quadbuf init (013) join with batch_001 shutdown; verify no LNK2005 with streaming_orchestrator on GOLD; harden Mode*/SO beyond empty stubs only if a real cathedral ABI owner exists (not Digestion_scanner.asm).
