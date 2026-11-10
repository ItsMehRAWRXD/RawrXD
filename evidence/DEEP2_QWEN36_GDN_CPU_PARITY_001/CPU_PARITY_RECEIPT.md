# DEEP2_QWEN36_GDN_CPU_PARITY_001

## Scope

This receipt records independent scalar parity for the Qwen3.6 GDN
intermediate recurrence and recurrent state on every GDN-bearing block emitted
by the CPU benchmark. It does **not** certify full-model logits parity,
Vulkan GDN, GPU placement, or production quality.

## Provenance

```ini
WORKSPACE=F:\\rawrxd
GIT_HEAD=2fcba4e60bcb8d5507134c2153c9245966de8602
EXECUTABLE=F:\\rawrxd\\build_reap\\bin\\deep2_bench_tps.exe
EXECUTABLE_SHA256=FBBA1A8AE1F82764F420E2B5E8A7A1ED045EC64EA95A89D2047614AD6BE45E12
MODEL=F:\\OllamaModels\\Qwen3.6-35B-A3B-GGUF\\Qwen3.6-35B-A3B-Q4_K_M.gguf
BACKEND=CPU_PINNED
COMMAND=--tokens "1 185" --decode 2 --cpu --serial-prefill --no-batch
INDEPENDENT_REFERENCE=tools/qwen36_gdn_cpu_parity.py
SCHEMA=rawrxd.qwen36.gdn.cpu.parity.v1
MAX_ABS_TOLERANCE=2e-5
PROMOTE=0
```

## Runtime witness

```ini
RUN_EXIT=0
CLEAN_RERUN_EXIT=0
BLOCKS_TOTAL=40
GDN_BLOCKS_DUMPED=30
GDN_BLOCKS_EXPECTED=30
STEPS_PER_BLOCK=3
COMPARISONS=90
COMPARISONS_PASSED=90
COMPARISONS_FAILED=0
LOGITS_FINITE=YES
GENERATED_TOKENS=2
GENERATED_TOKEN_IDS=9022 787
CPU_GDN_EXECUTION=PASS_REPORTED
CLEAN_RERUN=PASS_REPORTED
```

The remaining ten transformer blocks are non-GDN blocks for this architecture;
the 30 dumped blocks cover every block that entered the GDN recurrence.

## Aggregate parity metrics

The per-block JSON receipts are `parity_all_b*.json`; the aggregate summary is
`qwen36_gdn_cpu_parity_all_summary.json`.

```ini
MAX_OUTPUT_ABS=1.05177272828882e-05
MAX_STATE_ABS=8.95307993076244e-07
MAX_OUTPUT_MEAN_ABS=1.20078354695344e-08
MAX_STATE_MEAN_ABS=2.33849809735974e-10
MAX_OUTPUT_RMS=1.92353580822554e-07
MAX_STATE_RMS=3.60471680433286e-09
TOLERANCE=2e-5
INTERMEDIATE_PARITY=PASS_REPORTED
```

All 90 comparisons were computed by the independent Python scalar recurrence,
not by calling the Deep2 implementation. The dump source is the CPU execution
path after the production GDN step, with block and token identity retained in
each filename.

## Open gates

```ini
FULL_MODEL_LOGITS_PARITY=NOT_VERIFIED
FULL_MODEL_TOKEN_PARITY=NOT_VERIFIED
VULKAN_GDN=FAIL_CLOSED
GPU_NUMERICAL_PARITY=NOT_CERTIFIED
GPU_CPU_PLACEMENT_AB=NOT_RUN
REAL_MODEL_QUALITY=NOT_CERTIFIED
DIRTY_TREE=PRESERVED
PROMOTE=0
```

This receipt upgrades only the CPU GDN intermediate/state parity gate. It does
not promote the Qwen3.6 path to production inference certification.
