# Deep2 Kimi K2 performance accounting — 2026-10-27

This receipt records one real one-token Kimi K2 stream run after adding the
`GENERATION_WALL_ACCOUNTING_001` diagnostic surface. It is an attribution
receipt, not a throughput or numerical-parity certification.

## Provenance

- Build target: `rawrxd_deep2_engine` (Release, `F:\rawrxd\build_ide`)
- Executable: `F:\rawrxd\build_ide\bin\rawrxd_deep2_engine.exe`
- Executable SHA-256: `0515A2F3DF8CA3F9A5C1448EA6277CBC0967F1D26519A18A2B51741BF5267FD9`
- Model input: Kimi K2 Q4_K_M shard `00001-of-00013.gguf`
- Runtime exit: `0`
- Runtime elapsed: `62929 ms` (includes process setup/teardown)
- Runtime log SHA-256: `DDA5334FD6E8476BEF1B7A98D268A71DA3C44A0A555251B3FF97315B7DA745A8`

## Observed one-token receipt

```ini
TOKEN_COUNT=1
WALL_NS=46419212000
SHARD_READ_EXPOSED_NS=1952937000
SHARD_READ_BYTES=7670261696
SHARD_READ_OPS=915
MLA_EXPOSED_NS=1081614000
MLA_STAGE_SUM_NS=1080047000
GPU_GEMV_KERNEL_NS=0
GPU_UPLOAD_BYTES=0
H2D_TRANSFER_BYTES=0
MOE_GPU_WORK_NS=0
MOE_SHARD_IO_NS=10950798000
LOGITS_NS=155736000
UNCLASSIFIED_IF_DISJOINT_NS=42690978000
ACCOUNTING_COMPLETE=0
```

The run reached `T0_L39_EXIT` and exited successfully, but the binding line
was `DUALSTICK_BIND vc0=1 vc1=0 devices=1`. GPU1 execution is therefore not
proven. `GPU_GEMV_KERNEL_NS=0` and `H2D_TRANSFER_BYTES=0` also mean this run
does not certify GPU-resident MLA or MoE work.

`UNCLASSIFIED_IF_DISJOINT_NS` is deliberately named as a conditional residual:
the current timers are inclusive and can overlap. The accounting surface does
not subtract overlapping spans or claim a complete critical-path partition.

## Release decision

```ini
GENERATION_WALL_ACCOUNTING=CAPTURED
KIMI_K2_ONE_TOKEN_EXECUTION=PASS_REPORTED
WALL_ACCOUNTING=INCOMPLETE
GPU1_REAL_COMPUTE=NOT_PROVEN
GPU_RESIDENT_MLA=NOT_PROVEN
NUMERICAL_PARITY=NOT_TESTED
PERFORMANCE_CERTIFICATION=NOT_CERTIFIED
PROMOTE=0
```

The next performance change must add real CPU dequant/GEMV, H2D, KV-update,
and synchronization spans or prove that those paths are not active. Only then
can an optimization be evaluated against the Ollama baseline without double
counting or treating projected TPS as measured throughput.

## Opt-in per-expert attribution follow-up

The `DEEP2_MOE_ACCOUNTING=1` build was exercised against the same Kimi input
with one generated token. The first implementation attempted to snapshot the
64x512 matrix on the worker stack and correctly failed with Windows
`0xC00000FD`; that diagnostic defect was repaired by moving the snapshot to
heap storage before relying on the receipt.

The corrected run used executable SHA-256
`4D2E4AD64C946778FED15B36B7E6784578981FC025387CCF5707EB48A90E4331` and
exited `0`. It observed 480 selected and 480 executed experts across the 60
MoE layers, all on the CPU path (`MOE_GPU_EXECUTED=0`), with 480 acquisition
misses and no hits. Aggregate measured spans were:

```ini
MOE_EXPERT_ROWS=480
MOE_SELECTED=480
MOE_EXECUTED=480
MOE_CPU_EXECUTED=480
MOE_GPU_EXECUTED=0
MOE_ACQUIRE_HITS=0
MOE_ACQUIRE_MISSES=480
MOE_READ_BYTES=12768903168
MOE_GATE_GEMV_NS=3094576500
MOE_UP_GEMV_NS=2947374800
MOE_SILU_NS=4047500
MOE_DOWN_GEMV_NS=26369516200
MOE_TOTAL_NS=48132579000
MOE_ACCOUNTING_COMPLETE=1
```

The corresponding runtime receipt reported `WALL_NS=64835238000`,
`SHARD_READ_BYTES=7670261696`, `SHARD_READ_OPS=915`, `GPU_UPLOAD_BYTES=0`,
and `H2D_TRANSFER_BYTES=0`. The accounting run emits 480 per-expert rows and
is therefore diagnostic-only; its wall time must not be compared directly to
the quiet one-token run because receipt emission itself adds I/O. The result
does establish the first actionable optimization boundary: down-projection
GEMV accounts for 26.37 s of the measured 48.13 s expert total, while every
expert is reacquired on the host path. A bounded resident-slice experiment is
the next change; no model or routing policy is changed by this recorder.

## Final quiet-binary smoke run

After the accounting snapshot was moved off the stack, the rebuilt executable
was run again with accounting disabled to avoid receipt-I/O distortion. The
binary SHA-256 was `4CFC78A7EF6A6C889F16D4EC6A815938CC2AF2CD6E5E60E9C249CE60636389AA`.
The one-token Kimi run exited `0`, reached `T0_L39_EXIT`, and reported
`WALL_NS=50696723000` (50.697 s), `MOE_SHARD_IO_NS=13671149000`,
`STREAM_CACHE_HITS=2`, `STREAM_CACHE_MISSES=915`,
`GPU_GEMV_KERNEL_NS=0`, and `H2D_TRANSFER_BYTES=0`. This confirms the
instrumentation did not prevent the real host MoE path from completing; it is
not a performance certification and still does not prove GPU1 execution.
