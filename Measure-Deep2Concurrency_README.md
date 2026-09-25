# Measure-Deep2Concurrency.ps1 — DEEP2_CONCURRENCY_SCALE_001

## Classification
**AXIS_3 — CONCURRENCY_SCALING** (one of five orthogonal core scaling axes)

- Same model, same engine, same execution policy
- Varies: simultaneous stream count (AGENT_COUNT = 1, 2, 3)
- Primary metrics: `WALL_AGGREGATE_TPS_N`, `WALL_GAIN_N`, `PER_AGENT_RETENTION_N`
- Secondary diagnostic: `SUM_AGENT_DECODE_TPS` (must NOT replace wall aggregate)

## What it proves

Measures, rather than estimates:

- per-agent `eval_count` (generated tokens per agent)
- per-agent `eval_duration` (ns)
- per-agent decode TPS = `eval_count * 1e9 / eval_duration`
- total case wall time (from first request start to last completion)
- **wall aggregate TPS** = total generated decode tokens / case wall seconds
- sum of per-agent decode TPS (reported separately, never confused with wall aggregate)
- concurrency gain vs. measured single-agent median
- per-agent TPS retention vs. single-agent median
- Windows GPU-engine utilization counters
- Windows dedicated-GPU-memory counters

## Why two aggregate TPS numbers exist

`SUM_AGENT_DECODE_TPS` is the sum of each response's own Ollama `eval_count/eval_duration` rate.

`WALL_AGGREGATE_TPS` is stricter for concurrency: all requests start together, and the harness divides total generated decode tokens by wall-clock time until all requests finish. This is the **primary** concurrency number.

## Usage — Nemotron 30B Phase A sweep

```powershell
# 1-agent baseline
pwsh -ExecutionPolicy Bypass -File .\Measure-Deep2Concurrency.ps1 `
  -Model "nemotron-3.5-lightning:30b" `
  -AgentCounts @(1) `
  -Runs 5 `
  -NumPredict 256

# 1→2→3 sweep
pwsh -ExecutionPolicy Bypass -File .\Measure-Deep2Concurrency.ps1 `
  -Model "nemotron-3.5-lightning:30b" `
  -AgentCounts @(1, 2, 3) `
  -Runs 5 `
  -NumPredict 256
```

If exact model byte count is known, add `-ModelPath` or `-ModelBytes`:

```powershell
pwsh -ExecutionPolicy Bypass -File .\Measure-Deep2Concurrency.ps1 `
  -Model "nemotron-3.5-lightning:30b" `
  -ModelPath "C:\path\to\model.gguf" `
  -AgentCounts @(1, 2, 3) `
  -Runs 5 `
  -NumPredict 256
```

## Outputs

```text
concurrency_results/
  agent_runs.csv
  case_runs.csv
  summary.csv
  DEEP2_CONCURRENCY_SCALE_001.txt (authority receipt)
```

### summary.csv fields

| Field | Meaning |
|-------|---------|
| `agent_count` | Number of simultaneous streams |
| `wall_aggregate_tps_median` | Primary metric: total tokens / wall seconds |
| `sum_agent_decode_tps_median` | Sum of per-agent eval_count/eval_duration rates |
| `mean_agent_decode_tps_median` | Average per-agent decode rate |
| `concurrency_gain_wall_x` | `WALL_AGGREGATE_TPS_N / WALL_AGGREGATE_TPS_1` |
| `per_agent_retention_x` | `MEAN_AGENT_DECODE_TPS_N / SINGLE_AGENT_DECODE_TPS` |
| `vram_bytes_per_extra_agent` | Approximate VRAM increase per added agent |

## Authority flags in receipt

```text
MODE=MEASUREMENT_ONLY
TPS_INPUT_ACCEPTED=0
TPS_FROM_EVAL_COUNT_AND_EVAL_DURATION=1
GPU_PERCENT_USED_FOR_TPS=0
MODEL_SIZE_EXTRAPOLATION=0
```

## Important VRAM caveat

Windows' `GPU Adapter Memory(*)\Dedicated Usage` counter is emitted per adapter instance. This harness reports the **sum across all adapters** and labels it:

```text
GPU_VRAM_METRIC=ALL_ADAPTERS_DEDICATED_USAGE_SUM_NOT_R9700_SPECIFIC
```

This avoids pretending the Windows counter has been mapped to the R9700 when it has not. TPS measurements remain exact even if GPU performance counters are unavailable.

## Recommended authority run

For the three-agent Nemotron observation, use at least 5 repetitions and keep prompt, token count, endpoint, and model identical across 1/2/3-agent cases. Compare medians, not a single best run.

## Phase integration

This script implements **Phase A** of the DEEP2_EMPIRICAL_SCALING_AUTHORITY_002 execution order:

```
Phase A: Nemotron 30B 1→2→3 simultaneous-agent sweep
Phase B: Cross-model single-stream sweep (exact bytes only)
Phase C: Effective bytes/token and physical-residency instrumentation
Phase D: Hex Mag orchestration scaling
Phase E: Token Beacon Ferris implementation scaling
Phase F: Context/KV-length sweep
Phase G: Endurance / latency-tail / quality certification
Phase H: Only after sufficient distinct-model evidence: fit alpha, fit beta
```

## Five orthogonal axes reminder

```
AXIS_1 = MODEL_SCALING        — distinct exact model-size scaling (α when SIZE_X != 1)
AXIS_2 = IMPLEMENTATION_SCALING — same model, different engine/config (Token Beacon Ferris)
AXIS_3 = CONCURRENCY_SCALING  — genuine simultaneous-stream scaling (this script)
AXIS_4 = RESIDENCY_SCALING    — physical/effective working-set scaling
AXIS_5 = SWARM_HEX_MAG_SCALING — orchestration rather than simultaneous inference
```

This script produces **AXIS_3** evidence. Do not mix its results into AXIS_1 (model scaling) or AXIS_2 (implementation scaling) claims unless the independent variables required by both classifications are explicitly measured and held fixed.
