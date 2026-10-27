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
