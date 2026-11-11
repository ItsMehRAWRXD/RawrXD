# RawrXD / Deep2 Engineering Audit

Date: 2026-10-22  
Scope: native `rawr run`, daily agent path, Vulkan execution, dual-GPU profiling

## Completed and evidenced

- Native `rawr run <model> <prompt>` resolves local models, streams stdout, records JSON receipts, propagates exit status, and supports CPU/GPU/auto selection.
- Daily audit wrapper completed successfully with timeout, stdout/stderr capture, durable receipt, and deterministic read-only audit completion.
- Single-GPU Llama 3.2 Q2_K execution passed multi-token smoke and sustained runs with zero unplanned fallback and zero strict violations.
- Both discrete GPUs are enumerated and selected: R9700 slot 0 and RX 7800 XT slot 1.
- Opt-in dual-row execution completed with real dispatches on both devices; receipts report per-slot dispatch counts and `dual_physical_gpu=true`.
- Q2_K, Q3_K, Q5_K and related Vulkan quantized paths have build/component evidence; Q5_K production fallback gap was addressed.
- Session 3A completed 24 runs with three repetitions across 8/32/128/256 tokens in single and dual modes.
- Session 3B receipts expose calibrated GPU timestamps, queue submits, weight uploads, cache hits, and per-device counters.
- Queue Balance 3C receipts expose CPU submit and fence-wait totals per device.
- Batch 2 wait attribution trace emits device ordinal, submission ID, work kind, submit CPU time, wait time, GPU time, and bytes under `DEEP2_WAIT_TRACE=1`.
- Release build and `rawr_deep2_native_primitives` CTest pass after the attribution changes.

## Not certified

- `100+ TPS`: not achieved; best reported sustained result remains approximately 13 TPS on the tested Llama workload.
- Full Qwen4Exp/Qwen3.5 model certification: not established.
- Independent full-model logits parity and long autoregressive parity for every installed model: not complete.
- Multi-slot command-buffer ring: not implemented and correctly remains unpromoted.
- Dual-GPU performance advantage: not demonstrated on the matched 32/128/256 matrix; dual mode was slightly slower.
- Exact redundant-wait identification: pending correlation of trace submissions to producer/consumer dependencies.
- Autonomous source mutation with build/test/rollback: daily audit is verified; autonomous repair is not fully certified.

## Next 15 moves

1. Aggregate Batch 2 wait traces by device, work kind, token, and submission.
2. Correlate each wait with its producer/consumer dependency and fence/timeline value.
3. Separate legitimate GPU completion waits from host staging and residency waits.
4. Measure upload bytes and transfer intervals per submission.
5. Reproduce the matched 32/128/256 matrix with trace mode enabled and disabled.
6. Identify one demonstrably redundant or over-broad wait without changing behavior.
7. Apply one narrowly scoped synchronization change behind a feature flag.
8. Run correctness and parity checks against the unchanged baseline.
9. Repeat the matched matrix and require a repeatable TPS improvement.
10. Keep the change only if wait time and wall time both improve.
11. Evaluate existing fused command reuse before considering a multi-slot ring.
12. Add adaptive single/dual selection from measured break-even lengths.
13. Add profiling-overhead comparison to the authoritative receipt.
14. Certify streaming cancellation, disconnect, and lifecycle recovery.
15. Run per-model full-model certification and produce a release receipt.

## Current verdict

`NATIVE_GATEWAY=PASS`  
`DAILY_READ_ONLY_AUDIT=PASS`  
`SINGLE_GPU_SMOKE=PASS`  
`DUAL_GPU_EXECUTION=PASS`  
`WAIT_ATTRIBUTION=INSTRUMENTED`  
`FULL_MODEL_CERTIFICATION=NOT_CERTIFIED`  
`100_TPS=NOT_ACHIEVED`

No ring-0 bypass, physical-memory aliasing, unsafe driver exploit, or false certification was introduced.

## Batch 2 trace sample

An 8-token dual-GPU trace completed with exit `0`, zero fallback, and zero strict violations. Aggregated trace data showed:

- Device 0 kind 1: 925 waits, 225.260 ms total wait, 150.050 ms GPU time.
- Device 0 kind 2: 1,766 waits, 178.460 ms total wait, 40.840 ms GPU time.
- Device 2 kind 1: 141 waits, 32.060 ms total wait, 2.950 ms GPU time.
- Device 2 kind 2: 142 waits, 21.200 ms total wait, 11.050 ms GPU time.

This confirms submission/work asymmetry, but does not identify a redundant wait. Synchronization changes remain deferred.

## Batch 3 source classification

A fresh dual-device diagnostic completed with exit `0` using `DEEP2_WAIT_TRACE=1`; the receipt and captured streams are:

- `F:\\rawrxd\\evidence\\rawr_gpu0_wait_attribution_batch3_20261022.json`
- `F:\\rawrxd\\evidence\\rawr_gpu0_wait_attribution_batch3_20261022.stdout.log`
- `F:\\rawrxd\\evidence\\rawr_gpu0_wait_attribution_batch3_20261022.stderr.log`

The trace contained 1,966 wait records. Every sampled record classified as `wait_api=fence` with `dependency=queue_submit_to_fence` and `timeline_value=0`; no timeline-semaphore wait was observed in this path. Aggregated wait time was:

- Device 0, kind 1: 589 waits, 135.010 ms.
- Device 0, kind 2: 1,094 waits, 124.134 ms.
- Device 2, kind 1: 141 waits, 31.874 ms.
- Device 2, kind 2: 142 waits, 21.703 ms.

This establishes local queue-submission-to-fence completion as the sampled wait mechanism. It does not yet prove that any wait is redundant, identify a cross-device producer/consumer chain, or distinguish GPU-busy time from CPU-blocked time. No semaphore ordering, fence scope, or command scheduling change was promoted.

## Batch 4 fence critical-path reconstruction

The instrumented dual-device run completed with exit `0`, zero unplanned fallbacks, and zero strict GPU violations. The trace now carries submission ID, token, layer, host submit/wait intervals, calibrated GPU intervals, queue/command handles, and producer submission identity.

Summary evidence: `F:\\rawrxd\\evidence\\deep2_gpu_fence_critical_path_batch4_20261022.json`

- `1,966/1,966` waits were attributed to tokens `0-7` and Llama layers `0-27`.
- Device 0 kind 1: 589 submissions, 135.238 ms wait, 87.691 ms calibrated GPU, 87.481 ms overlap, 47.757 ms residual.
- Device 0 kind 2: 1,094 submissions, 125.117 ms wait, 33.415 ms calibrated GPU, 33.374 ms overlap, 91.744 ms residual.
- Device 2 kind 1: 141 submissions, 34.475 ms wait, 2.942 ms calibrated GPU, 2.942 ms overlap, 31.533 ms residual.
- Device 2 kind 2: 142 submissions, 22.089 ms wait, 11.212 ms calibrated GPU, 11.212 ms overlap, 10.877 ms residual.

The residual is defined as the recorded CPU wait interval minus its overlap with the calibrated GPU interval. It is a scheduling/queue attribution signal, not proven recoverable latency; clock calibration and overlapping submissions prevent summing it as wall-clock savings. The largest measured residual is Device 0 kind 2 at 91.744 ms across the trace. No cross-device producer dependency or redundant fence was demonstrated, so synchronization behavior remains unchanged.

### Batch 5 controlled candidate

Test exactly one feature-gated optimization: coalesce adjacent Device 0 kind-2 submissions within one layer only when they share the existing command-buffer/resource lifetime boundary and require no host readback. Preserve all cross-device, staging, and fence dependencies. Promote only if matched 32/128/256-token runs retain output correctness, zero fallback, zero strict violations, and show repeatable wall-time/TPS improvement.
