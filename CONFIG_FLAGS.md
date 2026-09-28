# RawrXD / Deep2 Configuration Flags Audit

## Environment Variables Found in `src/deep2/`

| # | Variable | File(s) | Purpose | Default | Conflicts | Risk |
|---|----------|---------|---------|---------|-----------|------|
| 1 | `DEEP2_BEACONISM` | `Beaconism.cpp` | Enable beaconism telemetry | off | — | Low |
| 2 | `DEEP2_BEACONISM_STDERR` | `Beaconism.cpp` | Beaconism stderr output | off | — | Low |
| 3 | `DEEP2_MODEL_PATH` | `deep2_openai_server_main.cpp` | Override model path | none | — | Low |
| 4 | `DEEP2_SERVER_PORT` | `deep2_openai_server_main.cpp` | Override server port | 11436 | — | Low |
| 5 | `DEEP2_OVERLAP_PROBE_EVERY` | `Deep2DualGpuRowSplit.cpp` | Overlap probe frequency | none | — | Low |
| 6 | `DEEP2_ASYNC_SPLIT_CONTROL` | `Deep2DualGpuRowSplit.cpp` | Async split control | none | — | Low |
| 7 | `DEEP2_SPLIT_INITIAL_RATIO` | `Deep2DualGpuRowSplit.cpp` | Initial split ratio | none | — | Low |
| 8 | `DEEP2_COLUMN_SPLIT_AUTO` | `Deep2DualGpuRowSplit.cpp` | Auto column split | none | — | Low |
| 9 | `DEEP2_ROW_SPLIT_AUTO` | `Deep2DualGpuRowSplit.cpp` | Auto row split | none | — | Low |
| 10 | `DEEP2_SPLIT_FREEZE_WINDOW` | `Deep2DualGpuRowSplit.cpp` | Freeze window size | none | — | Low |
| 11 | `DEEP2_SPLIT_FREEZE` | `Deep2DualGpuRowSplit.cpp` | Freeze split | none | — | Low |
| 12 | `DEEP2_GPU_FINITE_TRACE` | `Deep2Engine_GpuForward.cpp` | Enable GPU finite tracing | off | — | Low |
| 13 | `DEEP2_GPU_TRACE_PREFIX_HI` | `Deep2Engine_GpuForward.cpp` | Prefix trace high bound | none | — | Low |
| 14 | `DEEP2_WEIGHT_MODE` | `Deep2Engine_GpuForward.cpp` | Weight mode (resident vs stream) | resident | `WEIGHT_PREFETCH` | **Medium** |
| 15 | `DEEP2_WEIGHT_BUDGET_MIB` | `Deep2Engine_GpuForward.cpp` | Per-GPU weight budget | 512 MiB | `STICK0/1_BUDGET` | **Medium** |
| 16 | `DEEP2_STICK0_BUDGET_MIB` | `Deep2Engine_GpuForward.cpp` | GPU0 weight budget | none | `WEIGHT_BUDGET` | **Medium** |
| 17 | `DEEP2_STICK1_BUDGET_MIB` | `Deep2Engine_GpuForward.cpp` | GPU1 weight budget | none | `WEIGHT_BUDGET` | **Medium** |
| 18 | `DEEP2_WEIGHT_SLOTS` | `Deep2Engine_GpuForward.cpp` | Weight slot count override | none | — | Low |
| 19 | `DEEP2_WEIGHT_PREFETCH` | `Deep2Engine_GpuForward.cpp` | Enable weight prefetch | off | `WEIGHT_MODE` | **Medium** |
| 20 | `RAWRXD_Q2K_PRODUCT_DECODE` | `Deep2Engine_GpuForward.cpp`, `Deep2Engine_SsVkDecodeBind.cpp` (sets it) | Selects the 84-byte Vulkan Q2_K product route; refuses host F32 expand for Q2_K | off | — | Medium (route shader `gemv_q2k.spv` missing) |
| 21 | `DEEP2_SELF_DRAFT_LAYERS` | `Deep2Engine_Speculative.cpp` | Self-draft layer count | none | — | Low |
| 22 | `DEEP2_SPEC_WINDOW_CAP` | `Deep2Engine_Speculative.cpp` | Speculative window cap | none | — | Low |
| 23 | `DEEP2_REQUIRE_DUAL_GPU` | `Deep2Engine_VulkanRuntime.cpp` | Require dual GPU | off | — | Low |
| 24 | `DEEP2_REQUIRE_REFERENCE_PAIR` | `Deep2Engine_VulkanRuntime.cpp` | Require reference pair | off | — | Low |
| 25 | `DEEP2_ROPE_GPTJ` | `Deep2Engine.cpp` | RoPE GPT-J style override | off | — | Low |
| 26 | `DEEP2_TRACE_FORWARD` | `Deep2Engine.cpp` | Trace forward execution | off | — | Low |
| 27 | `DEEP2_LMHEAD_GEOMETRY_PROBE` | `Deep2Engine.cpp` | LM head geometry probe | off | — | Low |
| 28 | `DEEP2_DENSE_EXEC` | `Deep2Engine.cpp` | Dense execution mode | off | `RESIDENT_FIRST` | **Medium** |
| 29 | `DEEP2_RESIDENT_FIRST` | `Deep2Engine.cpp` | Resident-first routing | off | `DENSE_EXEC` | **Medium** |
| 30 | `DEEP2_GPU_POLICY` | `GpuScheduler.cpp` | GPU scheduling policy | auto | — | Low |
| 31 | `RAWRXD_MODEL_DIR` | `rawrxd_run_modelname_001.cpp` | Model directory | none | — | Low |
| 32 | `DEEP2_EXPERT_MIGRATION` | `test_generate_313_tokens.cpp` | Expert migration mode | default | — | Low |
| 33 | `RAWRXD_DEEP2_SHADER_DIR` | `vulkan_compute_tmp.cpp`, `vulkan_compute.cpp` | Shader directory override | none | — | Low |
| 34 | `DEEP2_Q4K_FORCE_TILE` | `vulkan_compute_tmp.cpp`, `vulkan_compute.cpp` | Force Q4_K tile size | none | — | Low |
| 35 | `DEEP2_Q4K_AUTOTUNE` | `vulkan_compute_tmp.cpp`, `vulkan_compute.cpp` | Enable Q4_K autotune | off | — | Low |
| 36 | `DEEP2_GPU_KV_SEQ_CAP` | `vulkan_compute_tmp.cpp`, `vulkan_compute.cpp` | KV sequence cap | none | — | Low |
| 37 | `DEEP2_RECORDED_GROUP_ASYNC` | `vulkan_compute_tmp.cpp`, `vulkan_compute.cpp` | Recorded group async | off | — | Low |
| 38 | `DEEP2_Q4K_FORCE_F32_VULKAN` | Not found in deep2 grep — may be in CMake or external | Force F32 for Vulkan Q4_K | off | — | High (A005) |
| 39 | `DEEP2_GPU_SOLO_STRICT` | Not found in deep2 grep — may be in CMake or external | Solo GPU strict mode | off | — | High (A003) |

## Red Flags

### Overlapping weight budget flags
- `DEEP2_WEIGHT_BUDGET_MIB` (global)
- `DEEP2_STICK0_BUDGET_MIB` (slot 0 override)
- `DEEP2_STICK1_BUDGET_MIB` (slot 1 override)

These three can conflict if all are set. No documented priority order.

### Conflicting execution routing
- `DEEP2_DENSE_EXEC` and `DEEP2_RESIDENT_FIRST` both affect how `generate()` routes to GPU vs CPU.
- `DEEP2_WEIGHT_MODE` and `DEEP2_WEIGHT_PREFETCH` both control weight residency behavior.

### Missing documentation
- `DEEP2_Q4K_FORCE_F32_VULKAN` — referenced in environment but not found in source grep
- `DEEP2_GPU_SOLO_STRICT` — same
- These may be handled in CMake, build scripts, or another layer.

### Q2_K route selector (corrected in Session 2)
- `RAWRXD_Q2K_PRODUCT_DECODE=1` is not an escape hatch. It selects the 84-byte Vulkan `DispatchGemvQuant` route and makes `Deep2Engine_GpuForward.cpp` refuse to expand Q2_K to F32 on the host.
- The 72-byte Q2_K MASM kernel it used to guard against is gone from the build: the `gemv_q2_k_masm` wrapper (never registered) was deleted and `sovereign_q2_k_gemv.asm` was removed from CMake. No value of this flag can reach MASM.
- Open issue: the shader this route needs, `gemv_q2k.spv`, does not exist in the tree, so Q2_K product decode is not proven to work.
