# DEEP2_REAP_EXPERT_PLACEMENT_AB_001

Disposition: `EXPERIMENT_INCOMPLETE` · `NO_SPEEDUP_CLAIM` · `PROMOTE=0`

## Authority

```ini
WORKSPACE=F:\rawrxd
BRANCH=fix/deep2-multimodel-safety-20261025
HEAD=2fcba4e60bcb8d5507134c2153c9245966de8602
SOURCE_DIRTY_TREE=PRESERVED
```

The experiment used the rebuilt `deep2_bench_tps.exe` from `F:\rawrxd\build_reap\bin`. No frozen product executable was modified or used as a replacement.

```ini
BENCH_BINARY_SHA256=D78F1348AC4446B89D74B4BAD38BDDB5964BFDC2BCFD0ED0DA18E353E91E29B3
```

## Existing controls used

```ini
DEEP2_MOE_PLACE_TRACE=1
DEEP2_MOE_PLACE_BUDGET_MIB=1024
DEEP2_WEIGHT_PREFETCH=0
DEEP2_MOE_GPU_ONLY=0
```

These are existing residency/placement controls. No parallel offload controller was added.

## Results

### Qwen3.6-35B-A3B Q4_K_M

Model: `F:\OllamaModels\Qwen3.6-35B-A3B-GGUF\Qwen3.6-35B-A3B-Q4_K_M.gguf`

Configuration: CPU baseline, two prompt tokens, decode `2`, one run.

Result: `FAIL_MODEL_ARCHITECTURE`

The model bound successfully (`arch=qwen35moe`, `experts=256`, `used=8`) but failed before execution:

```text
PREFILL_FAIL pos=0 err=GDN: GDN dimensions must be non-zero
```

No TPS, residency, or parity number is valid for this run. Full trace: `baseline_cpu_trace.txt`.

### DeepSeek-R1 Q4_K_M multi-shard

Model: `F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf`

Configuration: CPU baseline, two prompt tokens, decode `2`, one run.

Result: `FAIL_INGESTION_TIMEOUT`

The process was stopped after extended shard-ingestion activity without reaching bind, prefill, or decode. The trace confirmed DeepSeek MoE metadata (`expert_count=256`, `expert_used_count=8`) but produced no executable placement receipt. Full trace: `deepseek_cpu_trace.txt`.

## Certification impact

```ini
GPU_RESIDENT_BASELINE=NOT_RUN
CPU_RESIDENT_BASELINE=NOT_RUN
MIXED_PLACEMENT=NOT_RUN
PREFETCH_COMPARISON=NOT_RUN
REAP_POLICY_COMPARISON=NOT_RUN
NUMERICAL_PARITY=NOT_RUN
SPEEDUP=NOT_CLAIMED
```

These failures are useful compatibility findings, not evidence that the residency policy is ineffective. The next valid run must use a model/target that reaches actual expert execution, or first repair the Qwen3.6 GDN admission and DeepSeek multi-shard ingestion gates.
