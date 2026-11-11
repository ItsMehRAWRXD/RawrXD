# Deep2 performance repair integration

This is an instrumentation and ownership guard, NOT a replacement Vulkan backend or a proven speedup.

## Instrument real execution sites

- Immediately after a successful Vulkan `vkCmdDispatch` recording, call `telemetry.gpu_dispatch()`; distinguish recorded vs submitted/completed work in your native engine.
- At CPU graph execution, call `telemetry.cpu_op(is_fallback)`; define fallback as CPU execution of an operation originally scheduled for GPU.
- At GPU fence/queue waits, call `telemetry.gpu_sync()`.
- At host-to-device weight upload, call `telemetry.upload(bytes)`.
- Around batched prefill and decode, measure elapsed time with steady_clock and call `telemetry.prefill(tokens,ms)` or `decode(tokens,ms)`.
- After the engine validates its committed KV cache, call `telemetry.kv(reused,appended)` and update `PrefixTracker`. The tracker does NOT alter KV itself.

## GPU performance repairs requiring project-specific code

1. Trace graph op -> backend selection -> actual dispatch -> submission -> fence completion.
2. Replace per-token prefill with a correct batched graph path; preserve causal mask and positional offsets.
3. Keep immutable model weights resident across agent steps; avoid uploads in decode loop.
4. Use asynchronous submissions where dependencies permit, and synchronize only at required boundaries.
5. Ensure GGUF Q2_K/Q3_K/Q4_K and relevant MoE kernels have correct numeric parity; never silently report GPU if a CPU path runs.
6. Reuse KV only if token prefix, model weights, tokenizer, RoPE settings, attention configuration and KV state match. Invalidate on model change, cancellation with partial commit, or cache corruption.
7. Destroy the probe executor and synchronize its outstanding work before acquiring repair residency; an in-process gate does not guarantee Vulkan allocations are freed.
8. Emit `evaluate(snapshot,policy)` alongside raw counters; fail closed on missing dispatch when GPU is required.

## Build smoke test (MSVC Developer PowerShell)

`cl /nologo /std:c++20 /EHsc /W4 perf_guard_test.cpp /Fe:perf_guard_test.exe`
`./perf_guard_test.exe`

## Acceptance

- CPU-only test: gpu_dispatches=0, CPU ops >0, GPU-required gate fails.
- GPU test: dispatch/submission/completion counters nonzero; compare logits and token sequences against trusted reference.
- KV test: second turn prefill counts only genuinely appended tokens; model/token-prefix change forces recomputation.
- Residency test: two simultaneous model owners cannot acquire lease; GPU allocation accounting returns to baseline after teardown.
- End-to-end: same off-by-one repair, valid tool receipt, actual patch, successful build and test, measured latency reduction.
