# RAWRXD_DEEP2_MODEL_REGISTRY_001 — Batch 3 stub census

AUTHORITY: RAWRXD_SINGLE_WRITER_AUTHORITY_001
SCOPE: `rawrxd/CMakeLists.txt` + the Deep2 model-admission surfaces
MEASUREMENT_DATE: 2026-10-01
STATUS: CENSUS COMPLETE. Stub count NOT reduced. No CMake stub was removed.

Every number below was measured against the tree at `HEAD=94cd2fadf91431b5eaf8d61e52203d1b02268263`.
Nothing here is copied from a prior session's claims; where a prior figure is
referenced it is marked as unverified.

---

## 1. Headline counts (measured)

```ini
DEEP2_CPP_TOTAL            = 413   (exact; Get-ChildItem src/deep2 -Filter *.cpp)
DEEP2_HEADERS              = 627
DEEP2_CPP_NAMED_BY_CMAKE   = 208
CMAKE_NAMED_STUB_TUS       = 158   (measured; the "166" figure is NOT reproducible)
FILES_CONTAINING_STUB_STR  = 270   (of which 4 are large real TUs -> 266 true stubs)
FILES_LE_200_BYTES         = 275
REPO_WIDE_CPP              = 1935
REPO_WIDE_STUBISH          = 522
REPO_WIDE_CMAKE_NAMED_STUB = 245   (161 of them under src/deep2)
```

### 1.1 Reconciliation of the "274 / 166" figures

The commonly quoted `DEEP2_STUB_CPP=274` and `CMAKE_STUB_CPP=166` do **not**
reproduce under any single consistent definition:

| Definition | Count |
|---|---|
| contains the literal token `STUB` | 270 |
| ...minus 4 large real TUs that only mention STUB in comments | 266 |
| size <= 200 bytes | 275 |
| size <= 200 bytes **and** CMake-named (deep2) | 158 |
| size <= 200 bytes, `STUB`\|`return 0`, CMake-named (repo-wide) | 245 |

The 274 and 166 figures are close to the 275 and 158/161 measurements but do not
match any of them exactly. They should be treated as **stale**, not as a target.

`STUB_TU_CENSUS_COMPLETE` below is therefore stated against the measured 158,
with the discrepancy recorded rather than papered over.

---

## 2. THE FINDING THAT MATTERS

**Not one of the 158 CMake-named Deep2 stub TUs defines a single symbol.**

Every one of the 158 is either:

- `// STUB: src/deep2/<name>.cpp` — a comment-only file, zero declarations; or
- `int main(){ return 0; }` — a translation unit whose entire body returns 0.

Contents were dumped and read for all 158 (see the full enumeration below).

This changes the classification materially:

```ini
REQUIRED_RUNTIME = 0
```

No CMake-named Deep2 stub is standing in for missing *runtime* behaviour. None
of them can be, because they contribute no code. Removing or keeping them has
**zero** effect on what Deep2 can execute.

What they actually are is **unimplemented test and certification executables**.
That is a worse defect than a runtime stub, because of the second finding.

---

## 3. FALSE-PASS GENERATORS (the material risk)

Several of these stubs are wired as `add_executable(<name>_cert ...)` behind
`option(... OFF)`. Enabling the option produces a binary whose name asserts a
certification and whose exit code is unconditionally 0.

Example, measured at `CMakeLists.txt:9580`:

```cmake
option(BUILD_DEEP2_UCF_SEMANTIC_ABI_V1 "Build UCF_SEMANTIC_ABI_V1" OFF)
if(BUILD_DEEP2_UCF_SEMANTIC_ABI_V1)
add_executable(deep2_ucf_semantic_abi_v1_cert
src/deep2/deep2_ucf_semantic_abi_v1_cert.cpp)   # <-- int main(){ return 0; }
```

and at `CMakeLists.txt:16379`:

```cmake
if(TARGET InferenceEngine)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/test_o_proj_gemv.cpp")
add_executable(test_o_proj_gemv src/deep2/test_o_proj_gemv.cpp)  # <-- int main(){ return 0; }
```

These last two are **not** behind an `option(... OFF)`; only behind
`if(TARGET InferenceEngine)`. They build and pass by default in a configuration
where `InferenceEngine` exists.

```ini
NO_OP_CERT_EXECUTABLES_BUILT_UNCONDITIONALLY = 6
  test_o_proj_gemv
  test_o_proj_mulmat_002
  test_v_proj_parity
  test_attn_out_bisect
  test_gguf_alignment_diagnostic
  Deep2Engine_RouterSmokeTest

FALSE_SUCCESS_PATHS = 6   (must be 0 for RAWRXD_IDE_FINAL_001)
```

**Consequence for the ladder:** Batch 13 requires `FALSE_SUCCESS_PATHS=0`. These
six are already false-success paths today. They were not created by this batch
and were not removed by it, because removing a CMake entry is exactly the
"make the build green by dropping it" move the batch was told to avoid without
first establishing why the target is obsolete.

---

## 4. Per-TU classification of the 158

Categories as defined for this batch.

| Category | Count | Meaning |
|---|---|---|
| `REQUIRED_RUNTIME` | **0** | stub standing in for needed runtime behaviour → implement. None qualify: they define no symbols. |
| `REQUIRED_TEST` | **158** | stub standing in for a needed test/cert. All 158 are this. They are *not* implemented by this batch. |
| `OBSOLETE_DUPLICATE` | 0 | no stub duplicates a live implementation. |
| `QUARANTINED` | **132** | referenced only behind `option(... OFF)`; not built by default. |
| `UNREFERENCED` | **0** | every one of the 158 is referenced by CMakeLists.txt. |

```ini
STUB_TU_CENSUS_COMPLETE      = PASS   (all 158 individually enumerated + classified)
IN_BUILD_STUBS_UNACCOUNTED   = 0
REQUIRED_RUNTIME_STUBS       = 0
QUARANTINED_STUBS            = 132
CONDITIONALLY_BUILT_STUBS    = 26     (6 of which are no-op cert executables)
UNEXPLAINED_STUBS            = 0
```

### 4.1 The 26 built outside an `option(... OFF)`

26 stub TUs appear in source lists with no `option` gate. Two distinct shapes:

- **Comment-only stubs inside a library source list** (link-neutral, zero impact):
  `TheDualityExample`, `Deep2Server_Minimal`, `Deep2Server_Sovereign`,
  `GGUFLoader_Fixed`, `GGUFVerifier`, `dump_tensors`, `Deep2Engine_KernelTest`,
  `moe_microbench`, `moe_simple_bench`, `moe_test`, `moe_validation_test`,
  `router_bench`, `router_latency_test`, `test_api_server`,
  `test_real_gguf_load`, `test_real_gguf_validate`, `test_tool_limit_hotpatch`,
  `VAL063_Deep2Certification`, `VAL038_Benchmark_Harness`,
  `deep2_moe_bench_standalone`.

  Because a comment-only file declares nothing, it cannot be the sole source of
  an executable. These are inert.

- **No-op `main` executables** — the six false-pass generators listed in §3.

### 4.2 Full enumeration

All 158 CMake-named stub TUs, with their measured body. `// STUB:` files are
comment-only; `main0` files are `int main(){ return 0; }`.

```
_probe_chat_quality.cpp                                    main0
deep2_deepseek_live_gen_perf_cert.cpp                      // STUB
deep2_execution_policy_smoke.cpp                           // STUB
deep2_giant_moe_paragraph_perf_cert.cpp                    // STUB
deep2_gpu_dynamic_window_cert.cpp                          // STUB
deep2_gpu_forward_ops_cert.cpp                             // STUB
deep2_gpu_numeric_parity_cert.cpp                          // STUB
deep2_gpu_packed_forward_cert.cpp                          // STUB
deep2_gpu_q4k_gemv_cert.cpp                                // STUB
deep2_gpu_q6k_gemv_cert.cpp                                // STUB
deep2_gpu_quant_family_cert.cpp                            // STUB
deep2_gpu_resident_decode_cert.cpp                         // STUB
deep2_gpu_solo_cert.cpp                                    // STUB
deep2_gpu_solo_decode_cert.cpp                             // STUB
deep2_gpu_transfer_counter_cert.cpp                        // STUB
deep2_gpu_transfer_overlap_cert.cpp                        // STUB
deep2_gpu_weight_prefetch_cert.cpp                         // STUB
deep2_gpu_weight_window_cert.cpp                           // STUB
deep2_hybrid_all_hw_cert.cpp                               // STUB
deep2_k2_auto_workload_policy_cert.cpp                     // STUB
deep2_k2_e2e_model_size_matrix_cert.cpp                    // STUB
deep2_k2_full_depth_combined_policy_cert.cpp               // STUB
deep2_k2_full_depth_effectiveness_cert.cpp                 // STUB
deep2_k2_full_depth_fused_rebench_cert.cpp                 // STUB
deep2_k2_full_depth_trampoline_promotion_cert.cpp          // STUB
deep2_k2_gpu_copy_compute_overlap_cert.cpp                 // STUB
deep2_k2_gpu_mla_full_cert.cpp                             // STUB
deep2_k2_gpu_mla_full_depth_cert.cpp                       // STUB
deep2_k2_gpu_mla_nu_bridge_cert.cpp                        // STUB
deep2_k2_gpu_mla_re_cert.cpp                               // STUB
deep2_k2_gpu_mla_slot_reuse_cert.cpp                       // STUB
deep2_k2_gpu_stream_compute_cert.cpp                       // STUB
deep2_k2_gpu_stream_copy_cert.cpp                          // STUB
deep2_k2_gpu_stream_mla_cert.cpp                           // STUB
deep2_k2_live_decode_mla_cert.cpp                          // STUB
deep2_k2_live_decode_sustained_cert.cpp                    // STUB
deep2_k2_live_gen_perf_cert.cpp                            // STUB
deep2_k2_live_generate_policy_cert.cpp                     // STUB
deep2_k2_live_gpu_stream_e2e_cert.cpp                      // STUB
deep2_k2_live_policy_crossover_cert.cpp                    // STUB
deep2_k2_live_policy_e2e_cert.cpp                          // STUB
deep2_k2_live_policy_split_cert.cpp                        // STUB
deep2_k2_logits_climb_cert.cpp                             // STUB
deep2_k2_logits_gpu_range_attribution_001.cpp              // STUB
deep2_k2_logits_q6k_resident_cert.cpp                      // STUB
deep2_k2_logits_vwa_lineage_001.cpp                        // STUB
deep2_k2_mla_full_depth_soak_cert.cpp                      // STUB
deep2_k2_mla_fused_q4kt_cert.cpp                           // STUB
deep2_k2_mla_kv_expand_cert.cpp                            // STUB
deep2_k2_mla_kv_expand_opt_cert.cpp                        // STUB
deep2_k2_mla_qa_critical_cert.cpp                          // STUB
deep2_k2_mla_qkv_proj_cert.cpp                             // STUB
deep2_k2_mla_rebench_promote_cert.cpp                      // STUB
deep2_k2_mla_reuse_promote_cert.cpp                        // STUB
deep2_k2_policy_hysteresis_cert.cpp                        // STUB
deep2_k2_semantic_seal_cert.cpp                            // STUB
deep2_k2_serverless_stream_latency_cert.cpp                // STUB
deep2_k2_shard_attn_residency_cert.cpp                     // STUB
deep2_k2_stream_miss_reality_cert.cpp                      // STUB
deep2_k2_tps_rainbow_cert.cpp                              // STUB
deep2_k2_trampoline_full_depth_opt_cert.cpp                // STUB
deep2_k2_trygpu_logits_split_cert.cpp                      // STUB
deep2_k2_useful_tps_001.cpp                                // STUB
deep2_k2_wall_attribution_cert.cpp                         // STUB
deep2_live_path_effectiveness_cert.cpp                     // STUB
deep2_live_path_fused_control_cert.cpp                     // STUB
deep2_live_path_interaction_bounds_cert.cpp                // STUB
deep2_local_agent_audit_001.cpp                            // STUB
deep2_mars_e2e.cpp                                         // STUB
deep2_moe_bench_standalone.cpp                             // STUB
deep2_multi_gpu_layer_cert.cpp                             // STUB
deep2_nu_gemv_parity_cert.cpp                              // STUB
deep2_nu_gpu_gemv_cert.cpp                                 // STUB
deep2_nu_live_consumer_cert.cpp                            // STUB
deep2_nu_pack_format_cert.cpp                              // STUB
deep2_nu_perf_cert.cpp                                     // STUB
deep2_outer_engine_bridge_cert.cpp                         // STUB
deep2_parity_cert.cpp                                      // STUB
deep2_placement_cost_cert.cpp                              // STUB
deep2_rmv_mount_001.cpp                                    // STUB
deep2_runtime_batch1_cert.cpp                              // STUB
deep2_runtime_batch2_cert.cpp                              // STUB
deep2_runtime_batch3_cert.cpp                              // STUB
deep2_streamer_cert.cpp                                    // STUB
deep2_streamer_parity.cpp                                  // STUB
deep2_topology_portability_cert.cpp                        // STUB
deep2_ucf_bounce_smoke.cpp                                 // STUB
deep2_ucf_bouncehouse_example.cpp                          // STUB
deep2_ucf_generation_ticket_001.cpp                        // STUB
deep2_ucf_gpu_ready_e2e.cpp                                // STUB
deep2_ucf_halo_spark_001.cpp                               // STUB
deep2_ucf_logits_range_bounce_001.cpp                      // STUB
deep2_ucf_mobility_fault_001.cpp                           // STUB
deep2_ucf_no_stale_dispatch_001.cpp                        // STUB
deep2_ucf_read_converge_001.cpp                            // STUB
deep2_ucf_semantic_abi_v1_cert.cpp                         // STUB
deep2_vwa_e2e_001.cpp                                      // STUB
deep2_vwa_iocp_range_001.cpp                               // STUB
deep2_vwa_poc_1_001.cpp                                    // STUB
deep2_vwa_range_contract_001.cpp                           // STUB
Deep2Engine_KernelTest.cpp                                 // STUB
Deep2Engine_RouterSmokeTest.cpp                            main0
Deep2OuterEngineBridge.cpp                                 // STUB
Deep2Server_Minimal.cpp                                    // STUB
Deep2Server_Sovereign.cpp                                  // STUB
Deep2StreamApi.cpp                                         // STUB
dump_qwen35_meta.cpp                                       // STUB
dump_tensors.cpp                                           // STUB
GGUFLoader_Fixed.cpp                                       // STUB
GGUFVerifier.cpp                                           // STUB
K2FullDepthCombined_Arm.cpp                                // STUB
K2FullDepthCombined_Proof.cpp                              // STUB
layer_harness.cpp                                          // STUB
LivePathFusedCert_Arm.cpp                                  // STUB
moe_microbench.cpp                                         // STUB
moe_simple_bench.cpp                                       // STUB
moe_test.cpp                                               // STUB
moe_validation_test.cpp                                    // STUB
p0_process_alive_001.cpp                                   // STUB
p1_ide_exec_policy_apply_001.cpp                           // STUB
p1_ide_exec_policy_live_gguf_001.cpp                       // STUB
p1_policy_sha_lifecycle_diag_001.cpp                       // STUB
p1_real_speedup_001.cpp                                    // STUB
p1_repeatability_state_drift_diag_001.cpp                  // STUB
p1_repeatability_trial_validity_diag_001.cpp               // STUB
qwen35_attn_contract.cpp                                   // STUB
ResidencyLease.cpp                                         // STUB
router_bench.cpp                                           // STUB
router_latency_test.cpp                                    // STUB
StreamerGpuSoloGate.cpp                                    // STUB
StreamerGpuSoloVk.cpp                                      // STUB
StreamerParity_Harness.cpp                                 // STUB
StreamerParity_Post.cpp                                    // STUB
test_api_server.cpp                                        // STUB
test_attn_out_bisect.cpp                                   main0
test_chat_template.cpp                                     // STUB
test_chat_template_unit.cpp                                // STUB
test_deterministic_replay.cpp                              // STUB
test_embed_q4k_token.cpp                                   // STUB
test_gguf_alignment_diagnostic.cpp                         main0
test_l10_ffn_inp_same_source.cpp                           // STUB
test_o_proj_gemv.cpp                                       main0
test_o_proj_mulmat_002.cpp                                 main0
test_q_elemdiff.cpp                                        // STUB
test_q4k_gemv_parity.cpp                                   // STUB
test_real_gguf_load.cpp                                    // STUB
test_real_gguf_validate.cpp                                // STUB
test_streaming.cpp                                         // STUB
test_tool_limit_hotpatch.cpp                               // STUB
test_v_proj_parity.cpp                                     main0
test_val_051_3_multi_token.cpp                             // STUB
TheDualityExample.cpp                                      // STUB
VAL038_Benchmark_Harness.cpp                               // STUB
VAL0517BaselineFixture.cpp                                 // STUB
VAL063_Deep2Certification.cpp                              // STUB
vwa_address_contract_001.cpp                               // STUB
vwa_poc_1_001.cpp                                          // STUB
vwa_range_contract_001.cpp                                 // STUB
```

---

## 5. Also measured, for completeness

Two Deep2 stubs named by CMake are NOT stub-marked and were counted separately
so they are not silently lost:

```ini
MoERouter.cpp                 (26 b)  -> #include "MoERouter.hpp"   [FORWARDING]
SovereignOutOfCoreRuntime.cpp (132 b) -> includes PlasmaGovernor.hpp [FORWARDING]
```

Both are include-only TUs whose real implementation is header-inline or lives in
another TU. They are link-neutral. Not counted in the 158.

Two large Deep2 TUs mention the token `STUB` in comments but are real
implementations, and were **not** counted as stubs:

```ini
Deep2Engine.cpp         (243171 b)  // "Old success stubs removed."
GpuScheduler.cpp        (11860 b)   // "fail-closed, not stub"
QuantKernelRegistry.cpp (87753 b)   // per-kernel stub comments
rawr_run.cpp            (10767 b)   // audit text mentioning "stubs"
```

Counting any of these four as a stub would have inflated the stub total by 4 and
misattributed working code as missing.

---

## 6. What this batch did NOT do, stated plainly

- It did not reduce the stub count. 274/158 did not become 20.
- It did not remove a single CMake entry.
- It did not implement any of the 158 `REQUIRED_TEST` stubs. They remain stubs
  and remain classified, not hidden.
- `MODEL_REGISTRY_CALLED_BY_LOADER` is **not** proven here; see RECEIPT.md.