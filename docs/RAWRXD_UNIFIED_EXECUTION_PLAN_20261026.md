# RawrXD Unified Execution Plan

Date: 2026-10-26
Canonical source root: `F:\rawrxd`
Active branch: `fix/deep2-multimodel-safety-20261025`

## Purpose

This document reconciles the IDE daily-driver plan and the REAP/Deep2 production plan into one dependency-ordered execution plan. It is a plan and evidence index, not a certification receipt. A gate is promoted only when the exact binary, model, source revision, inputs, outputs, timing, and failure behavior are recorded in an authoritative receipt.

Rules:

- Preserve the active working tree and unrelated changes.
- Never overwrite source GGUF shards or use an uncertified reduced model as production input.
- Never convert a successful build, token emission, or internal seal flag into a correctness claim.
- Never fabricate parity, quality, GPU, or UI evidence.
- Keep architecture admission fail-closed when an execution path is not implemented.

## Authoritative baseline

| Item | Current value | Evidence/status |
|---|---|---|
| Source | `F:\rawrxd` | Active checkout |
| Branch | `fix/deep2-multimodel-safety-20261025` | Pushed to origin |
| HEAD | `9c1769632073...` | Dense-prefix execution repair pushed |
| CLI | `F:\rawrxd\build_ide\bin-msvc\rawr.exe` | Build and configured CTest pass; hash must be refreshed after rebuild |
| REAP CLI | `F:\rawrxd\build_reap\bin-msvc\rawr-reap.exe` | Structural planning and fail-closed admission exercised |
| REAP replay | `F:\rawrxd\build_reap\bin-msvc\rawr-reap-replay.exe` | Real model execution exercised; current provenance must be refreshed |
| IDE | `F:\rawrxd\build_unified_clean\bin\RawrXD-Win32IDE-Native.exe` | Prior physical UI evidence; rebuild against current HEAD before promotion |

## Current family matrix

| Family | Real evidence | Current boundary | Next implementation |
|---|---|---|---|
| Kimi K2 / DeepSeek-style MLA | 13-shard load, 1,096 tensors, five-window replay, route metrics, continuous one/two-token replay | Execution only; CPU-backed; parity/calibration/rewrite not certified | Independent reference parity, continuous correctness, GPU admission |
| DeepSeek R1 | 11-shard load, 1,025 tensors, dense-prefix repair, one/two-token continuous replay | Execution only; repeated token and GPU=false; calibration unsealed | First-divergence parity and validated calibration corpus |
| MiniMax M2.7 | 3-shard load, 809 tensors, topology and tensor inventory | Correctly rejected by K2 MLA path; no standard streaming MHA/MoE executor | Implement and test a real standard MHA/MoE multi-shard executor before admission |
| Ollama local models | Direct Ollama and local agent fixture E2E evidence | Keep as daily-driver fallback; certify per-model routing separately | Repeatable model matrix and cancellation/isolation receipts |

## Dependency-ordered phases

### Phase 0 — Preserve and prove provenance

1. Record source revision, full hashes for CLI, REAP CLI, replay, and IDE.
2. Keep all new evidence under a timestamped directory and do not stage unrelated dirty files.
3. Rebuild in isolated directories from the canonical checkout using one serialized MSVC environment.
4. Attach every receipt to the exact binary and model hashes.

Exit: reproducible build manifests exist. This phase does not certify runtime behavior.

### Phase 1 — Shared admission and inventory

1. Verify every shard family, tensor count, byte range, alignment, and architecture metadata.
2. Verify topology reports distinguish MLA, standard MHA, dense FFN, and packed MoE tensors.
3. Keep unsupported architecture admission explicit and fail-closed.

Existing evidence: `evidence/reap_model_inventory_matrix_20261026.json`, `evidence/reap_topology_*.json`, and `evidence/reap_shard_verification_*.json`.

Exit: all three families are inventory-safe; execution support remains family-specific.

### Phase 2 — Native runtime by family

1. Complete DeepSeek/Kimi dense-prefix and MoE routing without missing mandatory weights.
2. Add finite checks at embedding, attention/RoPE, FFN, final norm, logits, and sampling boundaries.
3. Implement a separate `StandardMhaMoEStreamGate` for MiniMax. Do not route MiniMax into the K2 MLA gate and do not use a dummy VC, zero-output fallback, or synthetic success.
4. Add cancellation, model-switch, and unload tests for each supported family.

Exit: each supported family produces bounded real tokens with complete teardown and explicit CPU/GPU mode.

### Phase 3 — Independent numerical parity

1. Use an independently validated reference implementation or reference service with identical GGUF, tokenizer, template, tokens, positions, and greedy sampling.
2. Compare token IDs and intermediate tensors at the first divergence.
3. Require continuous prefill/decode with persistent KV state, finite values, and deterministic repeated runs.
4. Keep `reference_parity_pass=false` until the independent comparison passes.

Exit: `REAP_REFERENCE_PARITY_001` is a real, reproducible PASS for every family claimed as certified.

### Phase 4 — REAP calibration and reduction

1. Produce a certified calibration receipt with non-empty route metrics, continuous decode, finite outputs, and parity evidence.
2. Generate a deterministic selection manifest per layer, including packed expert slices, shared experts, router dimensions, tensor offsets, alignment, and estimated output bytes including metadata.
3. Run the quality suite on the original model before writing.
4. Enable a candidate-only writer in a separate output directory. Never modify the original shards.
5. Reopen every output shard, validate GGUF metadata/tensor offsets/quantization/alignment, and compare retained tensor bytes.
6. Run post-pruning inference and the same quality suite. Enforce target size and quality floor.

Exit:

```ini
REAP_CPU_E2E=PASS
CONTINUOUS_DECODE=PASS
REFERENCE_PARITY=PASS
CALIBRATION=PASS
EXPERT_SELECTION=PASS
MOE_PRUNING=PASS
GGUF_REWRITE=PASS
GGUF_RELOAD=PASS
POST_PRUNING_INFERENCE=PASS
QUALITY_FLOOR=PASS
TARGET_SIZE=PASS
SOURCE_INTEGRITY=PASS
```

GPU status is separate and may remain `NOT_CERTIFIED` until real dispatch evidence exists.

### Phase 5 — GPU and performance certification

1. Prove actual Vulkan queue submission, kernel completion, device attribution, and finite output.
2. Compare CPU and GPU outputs before measuring speed.
3. Run single-GPU and dual-GPU tests with transfer, residency, synchronization, and fallback counters.
4. Measure cold/warm prefill and sustained decode TPS; configured targets such as `STREAM_NORM_TPS=150` are not measurements.
5. Optimize only after correctness; record dispatch count and synchronization overhead so regressions are visible.

Exit: GPU mode is promoted only with parity and nonzero execution evidence. Dual-GPU promotion requires both devices to perform useful work and recover from device loss.

### Phase 6 — Native IDE and agent daily-driver certification

1. Rebuild the canonical IDE from the same source revision as the CLI.
2. Verify editor open/edit/save/reopen, full-drive explorer, breadcrumb paths, model selectors, GhostText accept/dismiss, chat rollback, and snapshot restore.
3. Verify PowerShell input/output/cancellation and that terminal panes do not overlay Output, Errors, Debug, or Problems.
4. Verify LSP initialize/diagnostics/completion/shutdown, debugger launch/break/step/inspect, browser render/navigation, and extension activation.
5. Verify the agent on a disposable fixture: read → edit → native build → test → verify → injected failure → exact rollback.
6. Repeat unattended startup/model-switch/chat/terminal/agent workflows and preserve crash dumps for any failure.

Exit: daily-driver certification is based on repeated physical/runtime receipts, not control enumeration or self-manifest output.

## Immediate execution queue

1. Rebuild `deep2_engine_lib` and `rawr-reap-replay` from HEAD `9c17696320...`; capture full hashes.
2. Re-run the DeepSeek two-token witness and retain its execution-only status.
3. Run a real independent reference comparison; do not create a PASS receipt until it is independent and deterministic.
4. Implement the MiniMax standard MHA/MoE streaming path behind explicit architecture admission, with unit and multi-shard runtime tests.
5. Complete the certified calibration corpus and only then revisit REAP rewrite authorization.
6. Rebuild the canonical IDE from the same HEAD and execute the physical daily-driver gates.
7. Keep Ollama as the usable fallback while native Deep2 and REAP remain gated.

## Promotion rule

The product is not fully certified while any required gate is `PENDING`, `BLOCKED`, `NOT_RUN`, or based only on reported output. Current evidence supports real execution progress and a working Ollama agent path; it does not yet support production REAP, MiniMax native inference, GPU parity, or full daily-driver certification.
