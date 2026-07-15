# Phase E.1 Validation Protocol

## Overview

This document defines the **locked validation protocol** for Phase E.1 execution. Any deviation from this protocol invalidates results.

## Environment Freeze (Required Before Each Run)

```powershell
.\freeze_environment.ps1
```

**Captures:**
- Git commit hash (working directory must be clean)
- Model SHA256 fingerprint
- GPU driver version
- ROCm/Vulkan version
- OS build
- Power profile
- Background processes

**Output:** `environment_lock.json` (SHA256 fingerprinted)

## Validation Protocol

### 1. Baseline First

**DO NOT apply patches initially.**

Collect baseline measurements:
- Prompt TPS
- Generation TPS
- TTFT
- Latency percentiles (P50, P95, P99)
- Memory usage
- Power consumption

**Minimum runs:**
- 10 warmups
- 30+ measured runs

### 2. Isolated Hotpatch Experiments

Each patch tested **independently**:

```
Experiment A: baseline → GEMM patch
Experiment B: baseline → attention patch
Experiment C: baseline → KV cache patch
Experiment D: baseline → scheduler patch
```

**DO NOT stack patches initially.**

**First question:** Does one live patch produce measurable TPS change?

### 3. Hotpatch Event Validation

Required metrics:

```json
{
  "patch_name": "attention_v2",
  "deployment": {
    "activation_ms": 3.2,
    "threads_paused": 0,
    "tokens_lost": 0
  },
  "state": {
    "kv_cache_preserved": true,
    "context_preserved": true
  }
}
```

### 4. Statistical Gate

**Baseline:**
- Mean TPS
- 95% CI
- Standard deviation

**Hotpatched:**
- Mean TPS
- 95% CI
- Standard deviation

**Analysis:**
- Welch's t-test
- Cohen's d effect size
- Confidence interval of difference

**Success criteria:**
```
Baseline:     186.6 ± 2.4 tok/s
Hotpatch:     205.9 ± 2.7 tok/s
Difference:   +19.3 tok/s
95% CI:       [16.8, 21.9]
p-value:      <0.001
Cohen's d:    1.65 (very large)
```

### 5. Success Criteria

| Metric | Threshold | Status |
|--------|-----------|--------|
| TPS improvement | >5% | REQUIRED |
| Statistical significance | p < 0.05 | REQUIRED |
| Effect size | d > 0.8 | REQUIRED |
| Hotpatch time | <10ms | REQUIRED |
| Token loss | 0 | REQUIRED |
| Context preservation | true | REQUIRED |

## Execution Order

### Run 1: Quick Validation
```powershell
.\build_and_run.ps1 -Model "phi-3-mini" -Patch "gemm"
```

### Run 2: Attention Patch
```powershell
.\build_and_run.ps1 -Model "phi-3-mini" -Patch "attention"
```

### Run 3: Full Matrix
```powershell
.\build_and_run.ps1 -Matrix
```

## Comparison Targets

```
RawrXD baseline
    vs
RawrXD hotpatched
    vs
Ollama baseline (external)
```

## The Complete Loop

```
Measure
   ↓
Identify bottleneck
   ↓
Apply live patch
   ↓
Measure again
   ↓
Statistically verify improvement
   ↓
Keep or rollback
   ↓
Audit result
```

## Evidence Package

Final artifact structure:

```
reports/phase_e/
├── validation_report.md
├── validation_report.json
├── validation_report.csv
├── validation_dashboard.html
├── charts/
│   ├── tps_baseline_vs_hotpatch.png
│   ├── latency_distribution.png
│   ├── stability_over_time.png
│   └── safety_score_breakdown.png
└── raw_data/
    ├── inference_samples.csv
    ├── hotpatch_samples.csv
    └── longrun_timeseries.csv
```

## Invalidation Conditions

Results are INVALID if:
- [ ] Working directory was dirty during freeze
- [ ] Model changed between runs
- [ ] GPU driver updated mid-test
- [ ] Background process consumed >5% CPU
- [ ] Fewer than 30 measured runs
- [ ] CV > 5% (high variance)
- [ ] Hotpatch time > 10ms
- [ ] Any tokens lost during patch

## Sign-off

Before accepting results:

- [ ] Environment frozen and fingerprinted
- [ ] Baseline established with clean runs
- [ ] Hotpatch applied and validated
- [ ] Statistical significance confirmed
- [ ] Effect size calculated
- [ ] No invalidation conditions met
- [ ] Evidence package generated

---

**This protocol ensures Phase E.1 results are reproducible, statistically valid, and publication-ready.**
