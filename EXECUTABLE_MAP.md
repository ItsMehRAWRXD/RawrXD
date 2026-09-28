# RawrXD / Deep2 Executable Map

| # | File | Directory | Entry Point | Purpose | Uses Deep2 Authority? | Notes |
|---|------|-----------|-------------|---------|----------------------|-------|
| 1 | `main.cpp` | `src/win32app/` | `int main(int argc, char** argv)` | IDE / runtime wrapper | TBD | Likely routes through IDE or benchmark path |
| 2 | `RawrXDAgenticE2E.cpp` | `src/agent/` | `int main()` | Agentic E2E harness | TBD | May use its own inference loop |
| 3 | `main.cpp` | `src/deep2/` | `int main(int argc, char* argv[])` | Deep2 CLI / benchmark | TBD | May be the primary `Deep2Engine` caller |
| 4 | `deep2_openai_server_main.cpp` | `src/deep2/` | TBD (compiled into exe) | OpenAI-compatible HTTP server | **Yes** | Already confirmed routes through `Deep2Engine` |
| 5 | `test_generate_one_token.cpp` | `src/deep2/` | `int main()` | Single-token oracle | **Yes** | Uses `Deep2Engine::generateUnified()` |
| 6 | `test_generate_313_tokens.cpp` | `src/deep2/` | `int main()` | 313-token gate | **Yes** | Uses `Deep2Engine::generateUnified()` |
| 7 | `test_q2k_single_tensor_oracle.cpp` | `src/deep2/` | `int main()` | Q2_K tensor oracle | **Yes** | Loads model weights directly, not full forward |
| 8 | `sovereign_chat_main.cpp` | `src/core/` | `int main()` | Sovereign chat demo | **No** | Likely uses `SovereignEngineController` |
| 9 | `sovereign_super_node.cpp` | `src/core/` | `int main()` | Sovereign super-node | **No** | Separate engine path |
| 10 | `SovereignIntegration_Execute.cpp` | `src/core/` | `int main()` | Sovereign integration | **No** | Separate path |
| 11 | `native_ide_tools_demo.cpp` | `src/core/` | `int main()` | IDE tools demo | TBD | May use `IDEEngine` |
| 12 | `native_ide_tools_test.cpp` | `src/core/` | `int main()` | IDE tools test | TBD | May use `IDEEngine` |
| 13 | `performance_benchmark.cpp` | `src/core/` | `int main()` | Performance benchmark | TBD | May route through `GenerationEngine` |
| 14 | `test_generation.cpp` | `src/core/` | `int main()` | Generation test | TBD | Unknown engine |
| 15 | `test_all_phases.cpp` | `src/core/` | `int main()` | All-phases test | TBD | Unknown engine |
| 16 | `test_streaming_inference.cpp` | `src/core/` | `int main()` | Streaming test | TBD | Uses `StreamingEngineRegistry`? |
| 17 | `backend_equivalence_test.cpp` | `src/core/` | `int main()` | Backend equivalence | TBD | Unknown |
| 18 | `test_sovereign_backend.cpp` | `src/core/` | `int main()` | Sovereign backend | **No** | Separate path |
| 19 | `test_sovereign_backend_real.cpp` | `src/core/` | `int main()` | Sovereign backend real | **No** | Separate path |
| 20 | `rawr_engine_link_closure.cpp` | `src/core/` | `int main()` | Link closure | TBD | May be compile/link test only |
| 21 | `scheduler_test.cpp` | `src/core/` | `int main()` | Scheduler test | TBD | Unknown |
| 22 | `layer_witness_test.cpp` | `src/core/` | `int main()` | Layer witness | TBD | Unknown |
| 23 | `kv_cache_witness.cpp` | `src/core/` | `int main()` | KV cache witness | TBD | Unknown |
| 24 | `batch_splitter_test.cpp` | `src/core/` | `int main()` | Batch splitter | TBD | Unknown |
| 25 | `test_attn_out_bisect.cpp` | `src/core/` | `int main()` | Attention bisect | TBD | Unknown |
| 26 | `test_llama_decode.cpp` | `src/core/` | `int main()` | Llama decode | TBD | Unknown |
| 27 | `test_v_proj_parity.cpp` | `src/core/` | `int main()` | V-proj parity | TBD | Unknown |
| 28 | `test_distillation.cpp` | `src/core/` | `int main()` | Distillation | TBD | Unknown |
| 29 | `test_deobf.cpp` | `src/core/` | `int main()` | Deobfuscation | TBD | Unknown |
| 30 | `test_e2e_splitter_decoder.cpp` | `src/core/` | `int main()` | E2E splitter | TBD | Unknown |
| 31 | `test_execution_contracts.cpp` | `src/core/` | `int main()` | Execution contracts | TBD | Unknown |
| 32 | `test_event_bus.cpp` | `src/core/` | `int main()` | Event bus | TBD | Unknown |
| 33 | `test_headless_interface.cpp` | `src/core/` | `int main()` | Headless interface | TBD | Unknown |
| 34 | `test_http_splitter_client.cpp` | `src/core/` | `int main()` | HTTP splitter | TBD | Unknown |
| 35 | `test_command_router.cpp` | `src/core/` | `int main()` | Command router | TBD | Unknown |
| 36 | `test_transformer_loop.cpp` | `src/core/` | `int main()` | Transformer loop | TBD | Unknown |
| 37 | `test_simple_decoder.cpp` | `src/core/` | `int main()` | Simple decoder | TBD | Unknown |
| 38 | `test_gguf_bridge.cpp` | `src/core/` | `int main()` | GGUF bridge | TBD | Unknown |
| 39 | `test_gguf_alignment_diagnostic.cpp` | `src/core/` | `int main()` | GGUF alignment | TBD | Unknown |
| 40 | `test_benchmark_suite.cpp` | `src/core/` | `int main()` | Benchmark suite | TBD | Unknown |
| 41 | `test_version.cpp` | `src/core/` | `int main()` | Version test | TBD | Unknown |
| 42 | `test_unified_config.cpp` | `src/core/` | `int main()` | Unified config | TBD | Unknown |
| 43 | `test_unified_session.cpp` | `src/core/` | `int main()` | Unified session | TBD | Unknown |
| 44 | `test_ui_mode_adapter.cpp` | `src/core/` | `int main()` | UI mode adapter | TBD | Unknown |
| 45 | `aperture_q4_0_reference.cpp` | `src/core/` | `int main()` | Aperture Q4_0 ref | TBD | Unknown |
| 46 | `aperture_q4_0_test.cpp` | `src/core/` | `int main()` | Aperture Q4_0 test | TBD | Unknown |
| 47 | `aperture_standalone_test.cpp` | `src/core/` | `int main()` | Aperture standalone | TBD | Unknown |
| 48 | `benchmark_avx512_intrinsics.cpp` | `src/core/` | `int main()` | AVX512 benchmark | TBD | Unknown |
| 49 | `test_avx512_intrinsics.cpp` | `src/core/` | `int main()` | AVX512 test | TBD | Unknown |
| 50 | `hash_check.cpp` | `src/core/` | `int main()` | Hash check | TBD | Unknown |
| 51 | `simple_mips32_test.cpp` | `src/core/` | `int main()` | MIPS32 test | TBD | Unknown |
| 52 | `ScreenPilotToolAuthorityBridgeSelfTest.cpp` | `src/core/` | `int main()` | ScreenPilot self-test | TBD | Unknown |
| 53 | `titan_hardening_audit_v4.cpp` | `src/core/` | `int main()` | Titan audit | TBD | Unknown |
| 54 | `agentic_masm_bridge.cpp` | `src/core/` | `int main()` | MASM bridge | TBD | Unknown |
| 55 | `agentic_reasoning_loop.cpp` | `src/core/` | `int main()` | Reasoning loop | TBD | Unknown |
| 56 | `release_checklist.cpp` | `src/core/` | `int main()` | Release checklist | TBD | Unknown |
| 57 | `super_node_parallel_stress_test.cpp` | `src/core/` | `int main()` | Super-node stress | TBD | Unknown |
| 58 | `_probe_chat_quality.cpp` | `src/core/` | `int main()` | Chat quality probe | TBD | Unknown |
| 59 | `rawrxd_run_modelname_001.cpp` | `src/deep2/` | none (library function `rawrxd_run_modelname_001()`) | Model name runner | **Yes** | Calls `Deep2Engine` directly. Has no `main()`; `_rawrxd_run_modelname_001_main.cpp` has one but is not in CMake |
| 60 | `rawr_run.cpp` | `src/deep2/` | `int main()` | `rawr run <model>` CLI | **Yes** (via item 59) | Target `rawr` builds only with `BUILD_RAWRXD_RUN_MODELNAME_001=ON` (off by default). Target does not compile `rawrxd_run_modelname_001.cpp`, so it will not link. No `rawr.exe` exists |

## Session 2 build status (build dir `rawrxd/build`, Release)

`InferenceEngine`, `deep2_benchmark`, `deep2_openai_server`, `test_q2k_single_tensor_oracle` and `rawrxd` all fail, before and after Session 2. After Session 2 every `src/deep2` file compiles; the 195 remaining errors are in non-Deep2 sources compiled into `InferenceEngine` (`rawrxd_inference.*`, `rawrxd_transformer*`, `core/rawrxd_core.h`, untracked `cpu_inference_engine.*`, `codec/compression.cpp` needing zlib, `engine/gguf_core.cpp`). Those are Session 2B authority-collapse candidates.

## Classification Summary

- **Confirmed Deep2 authority**: Items 4, 5, 6, 7 (server + oracles), 59, 60
- **Confirmed non-Deep2**: Items 8, 9, 10, 18, 19 (Sovereign path)
- **TBD / needs verification**: Items 1, 2, 3, 11–17, 20–59 (the bulk)
- **Likely dead / demo-only**: Items 11, 12, 21–58 (many are tests/demos)

## Key Risk
The `GenerationEngine` (item 13, `src/generation/generation_engine.h`) and `CPUInferenceEngine` (item referenced in multiple places) may be alternate inference authorities that do not route through `Deep2Engine`. This is the primary `A001` blocker.
