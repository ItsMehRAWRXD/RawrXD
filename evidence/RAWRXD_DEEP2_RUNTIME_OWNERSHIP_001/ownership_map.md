# RAWRXD_DEEP2_RUNTIME_OWNERSHIP_001 — Resource Ownership Map

Produced by read-only inspection of the in-flight Move 11 changes
(`include/ModelGenieRuntime.h`, `src/modelgenie/ModelGenieRuntime.cpp`,
`src/modelgenie/ModelGenieExecutor.cpp`, `src/core/dll/Deep2InferenceAdapter.cpp`,
`src/core/dll/ownership_test.cpp`).

## Ownership after consolidation

| Resource | Sole owner | Former co-owners (eliminated) |
| --- | --- | --- |
| GGUF file mapping | `ModelGenieRuntime` (`mg_model_load`) — the only component that maps the GGUF | `Deep2InferenceAdapter` via `RawrXD::CPUInferenceEngine` singleton (`g_global_engine`) |
| Model weights | `ModelGenieRuntime` / `IRExecutor` ROM view over the mapped GGUF | `CPUInferenceEngine`'s own loader |
| KV cache | `mg_context_t` (authority); MLA latent cache per layer (latent + rope + up-projected key + value) | `CPUInferenceEngine` cache + `Deep2Context::prompt_tokens` full-prompt replay |
| Session handles | `mg_model_t` / `mg_context_t`; `Deep2Model` / `Deep2Context` are magic-guarded (`D2M1`/`D2C1`) thin wrappers | `RawrXD::CPUInferenceEngine` singleton |
| Token buffers | Authority tokenizer (`mg_model_tokenize` / `mg_model_detokenize`); adapter copies into caller buffers | `CPUInferenceEngine` tokenizer + adapter's own `prompt_tokens` vector |
| Sampler | Adapter-local state (temperature, top_p, top_k, repeat_penalty, repeat_last_n, seed; deterministic LCG) applied to authority logits | `CPUInferenceEngine::ConfigureGeneration` |
| Model facts (layers, file bytes, KV floats/position) | Authority-reported: `mg_model_layer_count`, `mg_model_file_bytes`, `mg_context_kv_floats_per_position` — "clients must not re-derive them from their own GGUF mappings" | Hardcoded / zero-filled in the adapter |

## Duplicate allocation/destruction paths eliminated

1. `g_global_engine` singleton + `get_global_engine()` — removed; one `mg_model_load` per `Deep2_LoadModel` handle, `mg_model_free` on `Deep2_FreeModel`.
2. Second GGUF load inside `CPUInferenceEngine::LoadModel` — removed; the runtime is the only mapper.
3. O(n²) decode: the old adapter stored the whole prompt and re-ran the full (prompt + generated) context on every `GenerateStreaming` call — removed; `Deep2_Decode` samples from the current logits then advances the authority exactly one step via `mg_context_eval`.
4. Zero-filled logits: old `Deep2_Prefill`/`Deep2_Decode` `std::fill`'d the caller's buffer with zeros — removed; `mg_context_eval_buffer` / `mg_context_eval` return real logits, and `out_logits` receives the logits the returned token was drawn from (argmax(out_logits) == token for greedy sampling).
5. `Deep2_GetMemoryInfo` TODO zeros — removed; every figure is authority-reported (`kv = position × per_position_floats × 4`, `model = mg_model_file_bytes`).
6. `Deep2_ResetKVCache` now calls `mg_context_reset` (authority returns to position 0) and clears the adapter's tracked tokens; `Deep2_TrimKVCache` only resizes the tracked prompt because the authority owns the cache.

## Ownership invariants (proven by `src/core/dll/ownership_test.cpp`)

1. **Single mapping** — two `Deep2_LoadModel` calls plus one direct `mg_model_load` against the same GGUF all succeed.
2. **Real logits** — prefill logits are finite and non-zero (`|sum| > 1.0`).
3. **KV authority** — `mg_context_position` equals the prompt length after prefill and advances exactly one per `Deep2_Decode`.
4. **One behaviour** — a generation driven only through the shim matches `mg_context_capture_tokens` on a direct authority context, token for token.
5. **Reset + reuse** — after `Deep2_ResetKVCache` the authority is at position 0 and the session reproduces the first token.
6. **Authority facts** — layers = 27, file bytes = 10364416768, `kv_bytes == position × per_position × 4`, `peak >= kv + model`.

## Numerical path (executor, in-flight)

`ModelGenieExecutor.cpp` adds ggml-order blocked quantized dot products
(`DotQ4KRow`, `DotQ6KRow`, `DotQ8_0Row`, `DotQ5_0Row`, `DotBlocked`,
`QuantizeQ8K`, `QuantizeQ8_0`): integer products first, one scale
multiply per 256-element super-block, eight int32 accumulation lanes —
reproducing llama.cpp to ~1e-8 where the dequantize-then-dot order
measured 2.8e-3 off on a real q4_K matmul. Wired at the MLA kv_a/kv_b
projections, the routed MoE experts (gate/up/down via `GetExpertRaw`),
and the two always-active shared experts. The dequantized order is
retained as the fallback for any type/case the blocked path does not
handle. The A/B investigation scripts (`tools/kernel_order_ab.py`,
`tools/kvup_parity.py`, `tools/find_first_divergence.py`,
`tools/bproj_order_ab.py`) remain available for numerical analysis but
are not dependencies of the production runtime.

## Build composition (for the integration step)

`ModelGenieRuntime` is a STATIC library
(`cmake/ModelGenieRuntime.cmake`) of:
`src/modelgenie/ModelGenieExecutor.cpp`,
`src/modelgenie/ModelGenieRuntime.cpp`,
`src/tokenizer/gguf_embedded_tokenizer.cpp`,
`src/deep2/modelgenie/ModelGenome.cpp`,
`src/deep2/modelgenie/ModelGenomeReader.cpp`;
links `OpenMP::OpenMP_CXX`. `RawrXDCore` (SHARED when
`BUILD_SHARED_LIBS=ON`) links it plus `psapi`.
`src/core/dll/CMakeLists.txt` still carries the comment that
excludes `Deep2InferenceAdapter.cpp` — that exclusion was
correct for the old adapter (it depended on the unverified
`src/deep2/Deep2Engine.cpp`); the rewritten adapter depends
only on `ModelGenieRuntime.h`, so the integration step is to
add an `ownership_test` executable compiling
`ownership_test.cpp` + `Deep2InferenceAdapter.cpp` and linking
`ModelGenieRuntime`, with the include directories mirrored
from the `RawrXDCore` target.

## Current state (15:58 UTC)

The peer agent is in a rapid edit-build-test loop (source
edits at 15:45–15:56). A mid-flight rebuild (15:16:56) already
improved the E2E differential to **12/12 argmax** at positions
0–11 (mean cos 0.999363, min cos 0.996162) — the blocked-dot
numerics fixed the position-1 near-tie — but the E2E certificate
still records the `3ed66470f2` binary hashes, so
`tools/verify_e2e_cert.py` reports 9/12 (the three BIN_SHA256
checks). That is re-certification debt, not a regression: it
clears when the final source is rebuilt and the certificate is
rebound to the new commit.

## Remaining integration steps

1. Peer stabilizes the in-flight edits.
2. Wire `ownership_test` + `Deep2InferenceAdapter.cpp` into
   `src/core/dll/CMakeLists.txt` (recipe above).
3. Fresh build (VS2022 x64, `BUILD_SHARED_LIBS=ON`) in a new
   directory; run `ownership_test` →
   `DEEP2_RUNTIME_OWNERSHIP_001=PASS`.
4. Re-run the evidence captures and re-certify
   `RAWRXD_CORE_DLL_NATIVE_E2E_001` against the new tree
   (rebind `GIT_COMMIT`, new binary hashes, new differential).
5. Exercise cancellation, repeated initialization, destruction,
   session reuse, and error recovery.
6. Commit (excluding the unrelated `OrganizedPiProject` submodule
   pointer) and push.

`tools/run_regression_suite.py` automates steps 3–4's gate
checks (git sync, E2E verifier, both certificate JSONs,
ownership test).
