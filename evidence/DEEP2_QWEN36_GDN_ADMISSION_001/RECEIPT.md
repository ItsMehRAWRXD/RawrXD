# DEEP2_QWEN36_GDN_ADMISSION_001

## Scope

This receipt records the Qwen3.6 admission and CPU-reference execution run. It
does not certify Vulkan GDN, GPU numerical parity, expert placement, or REAP
performance.

## Provenance

```ini
WORKSPACE=F:\\rawrxd
GIT_HEAD=2fcba4e60bcb8d5507134c2153c9245966de8602
EXECUTABLE=F:\\rawrxd\\build_reap\\bin\\deep2_bench_tps.exe
EXECUTABLE_SHA256=25713432CFA9B5AF08A289D13E38D07B9806EB10661004D53CC833D718B5C09F
MODEL=F:\\OllamaModels\\Qwen3.6-35B-A3B-GGUF\\Qwen3.6-35B-A3B-Q4_K_M.gguf
MODEL_ARCH=qwen35moe
MODEL_BLOCKS=40
MODEL_EXPERTS=256
MODEL_TOPK=8
BACKEND=CPU_PINNED
PROMOTE=0
```

## Command

```powershell
$env:DEEP2_GDN_DIAG='1'
$env:DEEP2_GDN_OPERAND_DIAG='1'
$env:ATTN_TRACE='1'
$env:QUANT_TRACE='1'
$env:LINEAR_TRACE='1'
$env:DEEP2_NO_DOT_BATCH='1'
$env:DEEP2_NO_RUNTIME_FUSE='1'
& .\\build_reap\\bin\\deep2_bench_tps.exe `
  --model 'F:\\OllamaModels\\Qwen3.6-35B-A3B-GGUF\\Qwen3.6-35B-A3B-Q4_K_M.gguf' `
  --tokens '1 185' --decode 2 --cpu --serial-prefill --no-batch
```

Raw output: `qwen36_quant_assert_trace_fixed.txt`  
Exit record: `qwen36_quant_assert_trace_fixed_exit.txt`

A second run with all diagnostics disabled is recorded in
`qwen36_clean_cpu_run_post_dequant_guard.txt` with exit `0`.

## Results

```ini
GEOMETRY_ADMISSION=PASS
GDN_CHANNELS=4096
GDN_STATE_SIZE=128
GDN_GROUPS=16
GDN_KEY_HEADS=16
GDN_VALUE_HEADS=32
GDN_HEAD_DIM=128
GDN_STATE_ELEMENTS=524288
GDN_BLOCKS_REACHED=40/40
ATTENTION_GEOMETRY=PASS_FOR_RECORDED_RUN
Q4K_TRACE_ASSERT=REMOVED
LOGITS_FINITE=YES
GENERATED_TOKENS=2
PROCESS_EXIT=0
RUN_VERDICT=PASS_CPU_REFERENCE
```

The previous abort was caused by the diagnostic witness calling GGML's Q4_K
dequantizer with a 32-element request. Q4_K requires a complete 256-element
block. The witness now decodes one complete block and prints a bounded prefix;
the production projection math is unchanged.

Measured run values from the receipt output:

- bind: 59,229.6 ms (excluded from throughput)
- prefill: 8,044.3 ms
- decode: 3,712.5 ms for two generated tokens
- generated stream: token IDs `9022 787`
- CPU calls: 3,903; GPU calls: 0

The clean rerun also returned finite logits, the same generated token IDs
(`9022 787`), and `RUN1 VERDICT: PASS`.

The final clean rerun after the block-safe `DequantPrefix()` guard is recorded
in `qwen36_clean_cpu_run_post_dequant_guard.txt` and also returned exit `0`,
finite logits, token IDs `9022 787`, and `RUN1 VERDICT: PASS`.

An extended CPU recurrence run is recorded in
`qwen36_multitoken_cpu_run.txt` (exit `0`). It generated eight tokens after
the two-token prompt, all logits were finite, and the stream was:
`9022 787 241139 151353 26049 38955 195132 200704`.

## Open gates

```ini
CPU_NUMERICAL_PARITY=NOT_VERIFIED
MULTITOKEN_CPU_STATE=PASS_REPORTED
MULTITOKEN_REFERENCE_PARITY=NOT_VERIFIED
VULKAN_GDN=FAIL_CLOSED
GPU_NUMERICAL_PARITY=NOT_CERTIFIED
GPU_CPU_PLACEMENT_AB=NOT_RUN
REAL_MODEL_QUALITY=NOT_CERTIFIED
PROMOTE=0
```

The run proves that metadata admission, the Qwen GDN CPU reference, 40-block
execution, finite logits, and two-token generation complete without the former
assertion. It does not authorize enabling the Vulkan GDN stub or promote any
performance or parity claim.
