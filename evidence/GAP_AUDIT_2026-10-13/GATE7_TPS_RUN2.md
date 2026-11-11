# Gate 7 / S10 — Production TPS certification, RUN2 (D2 verified)

**Marker:** `RAWRXD_GATE7_TPS_001`
**Status:** execution **PASS**, performance target **OPEN** (measured, not met), D2 **PASS**

## Environment (exact model and device identity)

| Item | Value |
| --- | --- |
| Model | `F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` |
| Model bytes | 668,788,096 |
| Model SHA-256 | `9f ecc3b3cd76bba89d504f29b616eedf7da85b96540e490ca5824d3f7d2776a0` |
| Architecture | llama, blocks=22, embd=2048, heads=32, kv=4, rope_dim=64 (311 bound ops/position) |
| Device | AMD Radeon AI PRO R9700, Vulkan, compute queue family 0, AMD vendor 0x1002 |
| Other enumerated devices | RX 7800 XT (Vulkan), Direct3D12 devices (not selected) |
| Revision | working tree at `d09d513a2d` + uncommitted D2 batching work (this session) |

## Tooling

- `tools/deep2_bench_tps.cpp` (`build_deep2_bench_tps.bat`) — trace-free prefill/decode
  benchmark: no per-op dumps, no trace files, greedy autoregressive decode over the
  executor's persistent KV. Every reported counter is a delta over exactly the wall
  interval it is divided by.
- `tools/deep2_strata_bench.cpp` — independent trace-free S10 receipt + S07 counters.
- `tools/deep2_parity_trace.cpp --gpu` — serial GPU path (SetOpTrace disables grouping),
  used as the D2 serial reference.
- Per-dot GPU completion is guaranteed by the fence inside `ExecuteQuantDot`; every run
  additionally asserts `descriptor_sets_in_flight == 0` after its last token.

## Timing boundaries (reconciled — no overlapping timers)

All MS values are deltas over the phase named on the same line.
`kernel_ms` is a **host-wait alias** (it has always added the `vkWaitForFences` duration
to `wait_ms`); `gpu_ms` is read from the **device timeline** (VkQueryPool timestamps,
`timestampValidBits > 0` on this device, period confirmed non-zero).

Cold single run, 8 prompt tokens, 128 generated tokens (`bench_batch_cold2.log`):

| Phase | Wall ms | GPU ms (device) | Host wait ms | Submit ms | Submits |
| --- | --- | --- | --- | --- | --- |
| bind | 2,759.3 | — (excluded from TPS windows) | — | — | — |
| prefill (8 tok) | 2,324.8 | ~2,500 | ~2,400 | ~100 | ~700 |
| decode (127 steps) | 28,833.7 | **~23,400** | ~27,700 | ~150 | ~11,470 |
| total measured | 31,158.5 | 25,858.9 (**83.0%**) | 27,744.4 | 234.1 | 12,170 |

Warm pair (`bench_batch_warm_runs2.log`, same process, run 2):

| Metric | RUN1 (cold-in-process) | RUN2 (warm) |
| --- | --- | --- |
| Prefill TPS | 3.371 | **4.579** |
| Decode TPS | 3.726 | **4.449** |
| Steady decode TPS | 3.726 | 4.448 |
| First decode ms | 267.7 | 215.9 |
| GPU share of window | 75.5% | **85.2%** |
| Submits | 12,170 | 12,015 |

Independent S10 receipt (`strata_plain_cold.log`): prefill 1.75–2.22 TPS,
decode mean 4.42 TPS, p50 217.72 ms, p95 426.84 ms, `gpu_calls=11160 cpu_calls=0
fallback=<none> nonfinite_logits=0`.

## D2 — dependency-correct GPU submission batching: VERIFIED

Grouping rule (executor): consecutive LINEAR ops with the **same arena input**
(a block's q/k/v, its gate/up) queue into one command buffer behind one fence; the group
is flushed before any op that is not one of those Linears. Bias-carrying models, traced
runs, and the diagnostic dump hooks keep the single-submit path.

Evidence (`gate7_d2_batched_vs_serial_logits.txt`):

| Comparison | Positions | Bit-identical | Max abs | Cos |
| --- | --- | --- | --- | --- |
| Batched vs serial GPU (`deep2_parity_trace --gpu`) | 135/135 | **135/135** | **0** | 1.000000000000 |
| Batched vs same-binary `--no-batch` control | 135/135 | **135/135** | **0** | 1.000000000000 |

Resource counters (same 8+128-token workload):

| Metric | Serial | Batched | Delta |
| --- | --- | --- | --- |
| Submits | 21,080 | 12,170 | **−42.3%** |
| Waits | 21,080 | 12,170 | **−42.3%** |
| Submits per position | 155 | 90.1 | −42% |
| Decode TPS | 4.220 | 4.405 | +4.4% |
| cpu_calls / fallback | 0 / none | 0 / none | unchanged |

Numerical regression: **none** — bit-identical full-vocab logits at every position, and
the generated stream is token-for-token identical to the serial and unbatched streams.
Failure accounting: a failed `EndBatch` replays the group on the CPU fallback, converts
the GPU call counters, and corrects the op-trace dispatch receipts (`FlushDotBatch`).

## Where the decode time actually goes

With submissions cut 42%, TPS moved only +4.4% — because the device is the bottleneck:
**85.2% of the decode window is real GPU time** (25.9 s of 30.5 s, device timestamps),
and each callback's kernel processes one output row per invocation. Dispatch overhead is
now ~15% (host wait − device time, plus queue/fence latency). The next optimisation
target is the kernel dispatch geometry (tiled/row-vectorised matmul), not submission
count. This is why the 150 TPS target remains **OPEN**.

## S07 — speculative decoding counters (measured)

Harness: `tools/deep2_strata_bench.cpp --spec 64 --draft-k 4` (prompt-lookup drafting,
greedy target verification; the target model executes one forward per position).

| Workload | Proposed | Accepted | Rejected | Discarded | Chains | Acceptance | Target forwards |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ramp prompt (`1+(i*37)%1000`) | 4 | 0 | 1 | 3 | 1 | **0.0000** | 64 |
| Copy workload (repeating-cycle prompt) | 60 | 56 | 2 | 2 | 15 | **0.9333** | 64 |

Verification cost is honest: `verification_ms` ≈ decode wall (15,095.7 of 15,101.7 ms in
the spec run), and `draft_forward_calls=0` (the draft model is host-side n-gram
matching). Because the executor still executes one forward per position, **accepted
drafts yield no throughput yet**: spec decode 4.24 TPS vs plain 4.42 TPS. S07 stays
**OPEN**: the mechanism is implemented and measured (93.3% acceptance on a copy
workload), but speedup requires batched verification of multiple draft tokens per
forward, which is the D1 follow-on.

## Independent reference correctness (carried from the Gate 5 chain)

`tools/gate7_tps_reference_check.py`: the benchmark's own 136-token stream was
teacher-forced through the independent llama.cpp clone; **127/128** generated positions
agree token-for-token (the single miss is the position-7 near-tie whose reference
margin 0.0349 is below the measured error, Deep2's pick being the reference's rank-1
token). The D2 stream is token-identical to that baseline, so the result carries over.

## Reproduce

```
tools\build_deep2_bench_tps.bat
deep2_bench_tps.exe --model models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf ^
    --tokens "1 185 278 20606 23808 7936 14336 28416" --decode 128
deep2_bench_tps.exe ... --decode 1 --dump-logits <batched>
deep2_parity_trace.exe --model ... --tokens "<135 ids>" --outdir <serial> --gpu
py tools\gate7_d2_batched_vs_serial.py
deep2_strata_bench.exe --model ... --generate 64 --spec 64 --draft-k 4 [--repeat-prompt]
```

## Blocker / verdict

- Execution PASS: 128/128 tokens, finite logits, `cpu_calls=0`, `fallback=<none>`,
  VRAM peak 600.8 MB, RAM peak 1,018.9 MB, deterministic cold/warm streams.
- D2 PASS: 42% fewer submissions and waits, bit-identical logits.
- Performance OPEN: measured 4.405 decode TPS / 4.579 warm prefill TPS = 2.9% of the
  150 TPS floor; blocker = per-row kernel dispatch geometry (85% device time), plus
  serial speculative verification for S07.
