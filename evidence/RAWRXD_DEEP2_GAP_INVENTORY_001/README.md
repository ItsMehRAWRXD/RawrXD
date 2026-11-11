# RawrXD Deep2 Gap Inventory 001

Status: `INVENTORY_COMPLETE` · `BATCH_1_READY` · `PROMOTE=0`

This inventory is read-only evidence reconciliation for the canonical branch. It does not promote a build, replace a frozen product executable, or reinterpret historical receipts as current certification.

## Baseline

```ini
WORKSPACE=F:\rawrxd
BRANCH=fix/deep2-multimodel-safety-20261025
HEAD=2fcba4e60bcb8d5507134c2153c9245966de8602
ORIGIN_HEAD=2fcba4e60bcb8d5507134c2153c9245966de8602
DIRTY_TREE=PRESERVE
PROMOTE=0
```

The current rebuilt binaries and their hashes are recorded separately in `evidence/RAWRXD_CURRENT_BUILD_REGRESSION_001/CURRENT_BUILD_RECEIPT.md`. The historical close-path PASS remains bound to executable SHA `0DA72700674E4F9B3EB8400F3F6F9BEF1CAD1D7816701EC8ABD61C518D17B3D6` and is not inherited by the current build without rerunning the test.

## Batch 1 — runtime correctness

### B1-MLA: Kimi multi-window continuity

Status: `BLOCKED_NOT_CERTIFIED`

Evidence:

- `evidence/unified_plan_start_20261026/kimi_replay_final_receipt.json` — one window, one generated token, no GPU real-forward or reference parity.
- `evidence/unified_plan_start_20261026/replay_final_receipt.json` — 480 expert metrics and completion, but no GPU certification or calibration completion.
- Replay topology reports 61 unknown layers and zero attention layers while MLA and a 61-layer KV cache are active.

Primary sources:

- `src/deep2/Deep2Engine.cpp`
- `src/deep2/K2MLAAttention.cpp`
- `src/deep2/K2KVCache.hpp`
- `src/deep2/CompressedKVCache.cpp`
- `src/deep2/MlaCertProbe.cpp`

Acceptance: at least two windows; prefill/decode continuity; a position crossing the window boundary; finite logits; independent reference parity; multi-token generation; no stale cache reuse.

### B1-GPU: GPU dispatch and numerical reference

Status: `DEVELOPMENT_WITNESS_ONLY`

Evidence:

- `evidence/DUAL_GPU_FORWARD_20261028/RECEIPT.md` — real GPU0/GPU1 submissions, no CPU fallback, finite logits, byte-identical split-device outputs, but independent reference logits are absent.
- `evidence/RAWRXD_DEEP2_GPU_DISPATCH_001/certificate.json` — FP32 RoPE parity only; quantized projections, attention, softmax, V aggregation and MoE remain outside the certified scope.

Primary sources:

- `src/deep2/Deep2Engine_GpuForward.cpp`
- `src/deep2/Deep2DeviceManager.cpp`
- `src/deep2/Deep2MultiGpuLayerPlan.cpp`
- `src/deep2/GpuTransfer_Emit.cpp`
- `src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp`

Acceptance: provenance-matched executable/source; nonzero submissions on both devices; finite output; no CPU fallback; independent reference logits within frozen tolerances; device-loss recovery.

Important limitation: `Deep2Engine_GpuForward.cpp` explicitly rejects MLA topology. The dual-GPU witness therefore must not be represented as production Kimi MLA GPU support.

### B1-PHI3: independent reference logits

Status: `MISSING_REFERENCE`

Evidence: `evidence/DUAL_GPU_FORWARD_PHI3_20261028/RECEIPT.md` proves a development witness with GPU0/GPU1 execution and finite output, but contains no independent reference logits.

Primary sources:

- `src/deep2/runtime_graph_executor.cpp`
- `src/deep2/modelgenie/universal_gguf.cpp`
- `src/deep2/lavapath/Phi3FusedQkvAuthority.hpp`
- `src/deep2/lavapath/Phi3FusedFfnAuthority.hpp`

Acceptance: model/tokenizer hash binding; prefill and decode reference logits; fused-QKV split parity; residual parity; multi-token generation; GPU0 and GPU1 comparisons.

### B1-KIMI: first-failure and production runtime

Status: `FAIL_CLOSED`

Evidence:

- `evidence/DEEP2_KIMI_LAYER1_FFN_RESIDUAL_CERT_001/RECEIPT.txt` — one real token and 480/480 expert accounting, but old executable provenance, no independent parity, and `L0_DENSE_STUB=1`.
- `evidence/KIMI_LAYER39_SINGLE_002/k2_l39_e108_audit.json` — CPU/scalar pass; GPU differs from FP32 CPU by ~0.0109 max abs.
- `evidence/KIMI_LAYER39_FIRST_FAIL_001/RECEIPT.json` — GPU output matches the Q6_K×Q8_K oracle (~3.18e-7), so the observed difference is a quantization-contract mismatch, not evidence of corruption.

Primary sources:

- `src/deep2/K2NativeMoEFfn_ExpertGpu.cpp`
- `src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp`
- `src/deep2/K2NativeMoEFfn.cpp`
- `src/deep2/K2MLAAttention.cpp`
- `src/deep2/Deep2Engine.cpp`

Acceptance: no dense stub; 61-layer traversal; >=32 decoded tokens; finite logits; independent Q6_K×Q8_K parity; live repeatability; KV continuity; exact model and executable provenance.

## Batch 2 — integration and regression

### B2-CMAKE: target classification

Status: `PARTIALLY_CLASSIFIED`

The CMake audit identifies intentional exclusions with documented duplicate-symbol/ODR reasons (`K2MLA_telemetry.cpp`, `mars/DualGPUBackend.cpp`) and dedicated witness targets (`deep2_dualgpu_forward`, `deep2_gpu_certify`). These are not automatically missing production integrations. Any wiring change requires a target-specific link audit and a clean rebuild.

### B2-CLI: agent regression classification

Status: `FAILURES_CLASSIFIED_NO_SOURCE_PATCH`

Current-binary evidence: `evidence/RAWRXD_CURRENT_BUILD_REGRESSION_001/`.

- Qwen completed read/edit/readback, then repeated a completed call. The runtime correctly returned `TOOL_LOOP_DETECTED`; this is a truthful fail-closed result, not a reason to weaken the loop guard.
- Llama emitted `writeFile` before `editFiles`, so the later exact-match edit correctly failed. The tool registry's unique-match requirement must remain intact.

Primary sources:

- `src/rawrxd_cli_v2.cpp`
- `src/agentic/tool_core.hpp`
- `src/win32app/Win32IDE_AgenticLoopBridge.cpp`

Next acceptance: rerun with a stop-after-readback prompt and classify model protocol compliance separately from runtime safety. No source patch is justified by these receipts alone.

### B2-GUI: current-build runtime regression

Status: `PARTIAL`

Current build observations: main title-bar close PASS; Chat2 creation PASS; model selector update observed; cloud GhostText unchecked by default. Current-hash agent-dialog close and inline GhostText render/Tab/Escape remain unverified. The historical Chat2 close PASS is valid only for SHA `0DA727...`.

## Dependency order

1. Resolve the Kimi layer/topology diagnostic and establish a two-window test harness (B1-MLA).
2. Produce Q6_K×Q8_K reference receipts for the exact GPU witness and repeatability (B1-GPU/B1-KIMI).
3. Produce independent Phi-3 logits before calling the dual-GPU witness certified (B1-PHI3).
4. Re-run current-build CLI/GUI tests with separate model-protocol and runtime-safety classifications (B2-CLI/B2-GUI).
5. Revisit CMake only for a demonstrated missing production owner; preserve documented ODR exclusions (B2-CMAKE).

No item in this inventory authorizes promotion, frozen-product replacement, or production REAP rewriting.

## Batch 1 execution update

The first concrete wiring correction is now applied locally: `src/deep2/Deep2InferenceService.cpp` is included in `deep2_engine_lib` in `CMakeLists.txt`. This was the only source identified as a production-facing implementation with no active build-graph reference; the other reported omissions are intentional ODR/test-target exclusions.

Build evidence after the change:

```ini
BUILD_IDE_TARGETS=PASS
BUILD_REAP_TARGET=PASS
UNRESOLVED_EXTERNALS=0
HEALTH_PROBE_EXIT=0
REAP_HELP_EXIT=2_EXPECTED
DEEP2_ENGINE_SMOKE_EXIT=0
```

Current rebuilt binary hashes:

```ini
WIN32IDE_SHA256=7CF0046C5329A8472E31D35553293DD657DF3FA1E3D4A26D4B10A56D8CFAA156
RAWR_SHA256=E0E568CBE257AD7C59D09CE36A89962E6B8814CB5B78A0BE866559504334E564
RAWR_REAP_SHA256=CAE8A7AB3DC9CCED1C7B0DF6A3C9A545A70ED10B01D6EBBC238624CA31354743
HEALTH_PROBE_SHA256=F86BE08113C0E6D868FB511A76CA592E7FF6E160FFB8E4E7E32920D19C088AA3
```

`rawrxd_deep2_engine.exe` was also rebuilt from the same graph and launched with no model arguments. It exited `0` after printing its usage path and performing normal engine teardown; this verifies link/startup/cleanup only, not model inference.

This closes the build-graph gap only. It does not certify Kimi MLA multi-window behavior, GPU numerical parity, Phi-3 independent logits, or current-build GUI/CLI runtime behavior. Those remain open under the acceptance criteria above.

## Placement experiment status

`evidence/DEEP2_REAP_EXPERT_PLACEMENT_AB_001/RECEIPT.md` records the first controlled placement attempt. Qwen3.6 bound as a 256-expert model but failed at GDN admission; DeepSeek multi-shard ingestion did not reach execution before clean termination. No throughput or speedup claim was made.
