# Gate 4 Certification — Native Quantized Dispatch + Numerical Closure

**Date:** 2026-10-13
**Status:** **PASS (dispatch + numerical closure, two-token)**
**Reproduce:** `powershell -ExecutionPolicy Bypass -File tools\ci_gate4.ps1 -BuildDir build_gate4`
(prints `GATE4_CI: PASS`; every step's log lands under `evidence/GAP_AUDIT_<date>/gate4_ci/`)

---

## 1. Root cause (corrected from the previous report)

The previous investigation concluded "no QuantDot definitions exist". **That was a search over
the build target's source list, not the repository.** The five functions were fully implemented
and tracked at HEAD in `src/deep2/quant_dot_dispatch.cpp` (343 lines), driving the genuine
`::VulkanCompute` GPU engine in `src/vulkan_compute.cpp`.

The actual defect: the uncommitted `deep2_parity_trace` CMake target omitted **both** translation
units (`quant_dot_dispatch.cpp`, `vulkan_compute.cpp`) from its sources and did not link the
Vulkan loader — so `runtime_graph_executor.cpp` / `op_linear.cpp` linked with exactly
5 unresolved symbols: `QuantDot::DotBlocked/DotF16/BeginBatch/EndBatch/LastReceipt`.
The identical translation units were already compiled by the hand-rolled
`tools/build_deep2_parity_trace.bat`, which is why the original PASS at `5d3f086964` existed
only outside CMake.

**Correction (not stubs — the genuine implementation, wired into the build):**

| Change | File | Why |
| --- | --- | --- |
| Add `src/deep2/quant_dot_dispatch.cpp` + `src/vulkan_compute.cpp` to the target, link `Vulkan::Vulkan` | `CMakeLists.txt` (`RAWRXD_GATE4_LINK_001`) | Defines the 5 entry points and the engine they call; matches the bat's inputs |
| Register `gpu_quant_dot_verify` and `gpu_quant_dot_realweights` targets under the same Vulkan guard | `CMakeLists.txt` | Their kernel evidence previously existed only as hand-compiled tools |
| Create the dump directory; dump failure is now a hard error (exit 1) | `tools/deep2_parity_trace.cpp` (`RAWRXD_GATE4_DUMP_001`) | Fresh trees have no `parity_out/`; the old WARN silently dropped the parity inputs |
| Fix `stats_.gpu_calls/cpu_calls +=` → `=` | `src/deep2/runtime_graph_executor.cpp` | The per-executor counters are cumulative; adding them per token double-counted (465 vs 310) |
| Extend kernel verifier to the shapes a model really exercises | `tools/gpu_quant_dot_verify.cpp` (`RAWRXD_GATE4_KERNEL_GEOMETRY_001`) | Old suite stopped at 8 super-blocks; tinyllama ffn_down is Q6_K×22 blocks |
| New CI runner | `tools/ci_gate4.ps1` (`RAWRXD_GATE4_CI_001`) | Full gate is build-system reproducible; GPU-less machines fail, never skip-pass |

## 2. Dispatch certification (the original Gate 4 contract)

Model `models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` (22 blocks, llama arch), device
**AMD Radeon AI PRO R9700**:

| | CPU-native | GPU-native |
| --- | --- | --- |
| Result | `GATE4_PASS` (exit 0) | `GATE4_PASS` (exit 0) |
| dots / vulkan / cpu | 154 / 0 / 154 | 154 / 154 / 0 |
| gpu_calls / cpu_calls | 0 / 155 | 155 / 0 |
| fallback | `k-quant dot: force_cpu` (authorized pin) | `<none>` |
| All 6 assertions | PASS (executed, recorded, no-missing, no-unauthorized-fallback, finite, layers-bound) | same |

**Extra-call reconciliation (155 vs 154; the historical 197 vs 196):** `QUANT_TRACE=1` shows
exactly **155 k-quant dispatches = 22 × 7 named projections (154) + 1 `output.weight`** — the
language-model head, 32000×2048 Q6_K, also a quantized mat-vec dispatched through the same
QuantDot layer, whose op-trace name (`logits`) is outside the auditor's 7-name scope
{q,k,v,attn_proj,gate,up,ffn_out}. Per token: `gpu_calls = dots + 1`. The historical
197/196 was the same arithmetic on 28 blocks (28×7=196 + head).

**465 vs 310 resolved:** the two-token runs reported 465 = 155 + 310 because
`stats_.gpu_calls += gpu_calls_` added the *cumulative* counter once per token. After the fix,
2 tokens report 310 = 2 × 155. CI asserts the relationship.

**Batching (BeginBatch/EndBatch) preserves results:** DeepSeek-V2-Lite (MoE, 6 experts/block),
GPU, tokens 1,185 — batched vs `RR_NO_MOE_BATCH=1` single-call: **102400/102400 logits
bit-identical at both positions** (max abs 0, rmse 0) with identical dispatch accounting
(1208 gpu_calls either way; the batch submits one command buffer per phase per block instead
of one per expert dot). Receipts flow through `LastReceipt` (`used_gpu`, `gpu_rows`,
`fallback_reason` — the CPU-mode `force_cpu` reason and GPU-mode `<none>` come from it).

## 3. Kernel-level numerical parity (trusted reference)

Trusted reference = independent decode of the GGML block layouts (verifier CPU reference and
ggml `to_float` + float dot), compared on **real GGUF bytes** with the same Q8 activation:

* `gpu_quant_dot_verify`: **15/15 shapes PASS** — cosine 1.0000000000, rel ≤ 1.6e-7, including
  the exact model shapes `q4k_ffngate_5632x2048`, `q6k_ffndown_2048x5632` (22 super-blocks) and
  a 9/10/14/18/22-block Q6_K sweep.
* `gpu_quant_dot_realweights --weights blk.0.ffn_down.weight` (real Q6_K bytes, 64 rows):
  rel **1.46e-08** vs the integer-lane reference, 1.43e-08 vs ggml dequant+dot.

The GPU kernel is arithmetically exact at the dot level. **No kernel defect.**

## 4. First divergent tensor, cause, and correction

Two backends execute the *same* graph; the CPU dot is integer-exact, the GPU dot accumulates
in float. Divergence enters at fp-rounding level (~1e-7) and is then amplified by exactly two
**designed** mechanisms, both proven by controlled A/B:

1. **F16 KV-cache round-trip** (`runtime_graph_executor.cpp:1413`, llama.cpp-compatible
   `type_k=type_v=F16`): sub-ULP upstream differences flip the F16 rounding on cache write;
   1 F16 ULP (~5e-4) then propagates into every later position's attention output.
   *Proof:* `DEEP2_KV_F32=1` drops the first pos-1 divergence
   **`blk1 attn_out`: 7.8e-3 → 6.4e-7 relative** (back to kernel rounding) and improves
   pos-1 logits rmse 0.223 → 0.108, cosine 0.9965 → 0.9992.
2. **Q8 activation recode boundaries** (every quantized dot re-quantizes its activation to
   int8 per backend): a value within ~1e-7 of a rounding boundary codes 1 LSB differently,
   stepping that dot's output by ~1e-3 relative. First observed entry: pos-0
   **`blk0 ffn_out` 5.2e-4 relative** (blk0 gate/up/swiglu at 1e-7), pos-1 `blk1 ffn_out`.

Localization map (default config, CPU vs GPU): q/k/v 1e-7 → attn_out/ffn_out sporadic ~1e-3 →
residual stream carries to `blk21 resid2` (0.23 pos-0, 0.11 pos-1 relative of small-magnitude
tensors) → logits.

**Two-token full-vocabulary parity (default, llama.cpp-compatible F16 cache):**

| pos | argmax cpu/gpu | max_abs | rmse | cosine | top-1/5/10/50/100 |
| --- | --- | --- | --- | --- | --- |
| 0 | **2760 / 2760** | 0.3656 | 0.0651 | 0.99965 | 1/1, 5/5, 9/10, 47/50, 95/100 |
| 1 | **13 / 13** | 1.1044 | 0.2231 | 0.99651 | 1/1, 3/5, 8/10, 44/50, 93/100 |

With the KV amplifier removed (F32 cache), argmax still agrees (2760, 17418) and cosine rises to
0.99986 / 0.99915. All 32000 logits finite on every run.

**Acceptance thresholds (derived, not fitted):** kernel parity vs the integer/ggml reference
≤ 1e-4 (tool-enforced); no-kernel-defect condition = block-0 position-0 q/k/v/ffn_out agree to
≤ 1e-6 relative (observed ≤ 1.8e-7); argmax agreement at every tested position. The end-to-end
logit numbers are *reported evidence*, not threshold-tuned — their magnitude follows from the
two diagnosed amplifiers, each bounded by one ULP/LSB of the tensor scale.

## 5. Verdict

**Gate 4 = PASS.** Native quantized dispatch reaches the GPU (154/154 on real hardware), CPU
mode executes correctly, batching preserves results bit-exactly, receipts and every counter are
reconciled, the numerical closure passes with argmax agreement at all tested positions, and the
residual CPU/GPU difference is a characterized, bounded amplifier effect with a demonstrated
lever (`DEEP2_KV_F32=1`), not a kernel or dispatch defect.

**Outstanding by design (Gate 5+):** full-logit parity across more positions against an
external reference (Gate 5); KV-cache incremental-vs-recompute (Gate 6); architecture closure
(Gate 7); Gate 2 primitive provenance remains open and must not be represented as complete.
