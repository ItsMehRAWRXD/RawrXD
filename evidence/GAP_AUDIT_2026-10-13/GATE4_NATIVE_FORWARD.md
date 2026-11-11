# MODEL_GENIE_NATIVE_FORWARD_001 — Gate 4: native forward, zero unauthorized fallback

Date: 2026-10-13. Instrumentation: per-op dispatch evidence in the executor's
OpTrace (RAWRXD_GATE4_DISPATCH_001: selected backend, fallback reason, forced
pin), audited by `deep2_parity_trace.exe --gate4 <cpu|gpu>` on a real forward
pass of llama3.2:3b (28 layers, 395 bound ops).

## Acceptance contract results

| # | Condition | cpu-native | gpu-native |
|---|-----------|-----------|-----------|
| 1 | Every required forward operation executes | PASS (395 ops) | PASS (395 ops) |
| 2 | No unauthorized CPU or GPU fallback | PASS | PASS |
| 3 | No missing kernel silently became a success | PASS | PASS |
| 4 | All expected model layers execute | PASS | PASS |
| 5 | Forward pass produces finite logits | PASS | PASS |
| 6 | Host counters agree with dispatch events | PASS (cpu_calls=197, dots=196) | PASS (gpu_calls=197, cpu_calls=0) |
| 7 | Results tied to a source revision | this file + git | this file + git |

## Per-op dispatch evidence (samples)

CPU-native (SetForceCpu is the host policy pin — CPU is the SELECTED backend,
not a fallback):

    [q]         weight=blk.0.attn_q.weight       backend=cpu    forced=1
    [k]         weight=blk.0.attn_k.weight       backend=cpu    forced=1
    [v]         weight=blk.0.attn_v.weight       backend=cpu    forced=1
    [attn_proj] weight=blk.0.attn_output.weight  backend=cpu    forced=1

GPU-native (no pin):

    [q]         weight=blk.0.attn_q.weight       backend=vulkan forced=0
    [k]         weight=blk.0.attn_k.weight       backend=vulkan forced=0
    [v]         weight=blk.0.attn_v.weight       backend=vulkan forced=0
    [attn_proj] weight=blk.0.attn_output.weight  backend=vulkan forced=0

Totals: cpu config 196 dots ALL cpu (forced=1), zero unauthorized fallback.
gpu config 196 dots ALL vulkan, cpu_calls=0, fallback=none.

## Reproduce

    tools\build_deep2_parity_trace.bat
    deep2_parity_trace.exe --model M.gguf --tokens "1" --gate4 cpu
    deep2_parity_trace.exe --model M.gguf --tokens "1" --gate4 gpu --gpu

GATE4_PASS is emitted only when all seven conditions hold; a forced CPU pin is
reported as forced=1 (authorized), while any device substitution WITHOUT the
pin is counted as an unauthorized fallback and fails the gate.
