//============================================================================
// CI_STAGE_MAPPING.md
// RawrXD N-EVM - CI/CD Stage Mapping
// Documents PR CHECK vs NIGHTLY stages
//============================================================================

# RawrXD N-EVM CI/CD Stage Mapping

## Overview

This document defines the CI/CD pipeline stages for the RawrXD N-EVM validation framework.
The validation gates are distributed across PR CHECK (fast feedback) and NIGHTLY
(extensive testing) stages based on execution time and criticality.

## PR CHECK Stage (Target: < 5 minutes)

Fast feedback for every pull request. Fails fast on correctness issues.

### Gates Included

| Gate | Time Budget | Purpose |
|------|-------------|---------|
| Gate 1: Model Load | 30s | Verify model loads without corruption |
| Gate 2: Tokenizer | 15s | Validate tokenization round-trip |
| Gate 3: KV Allocation | 15s | Verify KV cache allocation |
| Gate 4: Single Inference | 60s | Basic inference correctness |
| Gate 5: Determinism | 30s | Bit-exact reproducibility |
| Gate 11: Schema Validation | 5s | Schema version compatibility |

### Exit Codes (PR CHECK)

- `0` - All gates passed, PR can merge
- `1` - Correctness failure (block merge)
- `5` - Invalid model (block merge)
- `6` - Schema mismatch (block merge)

### Artifacts (PR CHECK)

- `pr_check_report.json` - Machine-readable results
- `pr_check_summary.txt` - Human-readable summary
- Console output with color-coded pass/fail

## NIGHTLY Stage (Target: < 2 hours)

Comprehensive validation run nightly on main branch.

### Gates Included

All 11 gates plus extended stress testing:

| Gate | Time Budget | Purpose |
|------|-------------|---------|
| Gate 1-5 | 2m 30s | Same as PR CHECK |
| Gate 6: Math Mode | 5m | All three math modes |
| Gate 7: KV Integrity | 3m | Corruption detection |
| Gate 8: Plan Version | 2m | Execution plan freshness |
| Gate 9: Stress Test | 30m | 10,000 step soak |
| Gate 10: Regression | 10m | Performance comparison |
| Gate 11: Schema | 5s | Schema validation |
| Extended Stress | 45m | Lifecycle events |

### Exit Codes (NIGHTLY)

- `0` - All gates passed
- `1` - Correctness failure
- `2` - Performance regression
- `3` - Stability failure
- `4` - Environment failure
- `5` - Invalid model
- `6` - Schema mismatch

### Artifacts (NIGHTLY)

- `nightly_report.json` - Full machine-readable report
- `nightly_summary.txt` - Human-readable summary
- `performance_trends.json` - Historical comparison
- `failure_artifacts/` - Captured state on failure
- `golden_output_tests/` - Deterministic output validation

## Stage Decision Matrix

```
PR CHECK:
  Trigger: Every PR
  Duration: < 5 minutes
  Gates: 1, 2, 3, 4, 5, 11
  Block Merge: Yes (on exit code != 0)
  
NIGHTLY:
  Trigger: Daily 02:00 UTC + every merge to main
  Duration: < 2 hours
  Gates: All 11 + Extended Stress
  Block Merge: No (informational)
  Alert: Slack #nightly-builds on failure
```

## CI Configuration Examples

### GitHub Actions

```yaml
# .github/workflows/pr-check.yml
name: PR Check
on: [pull_request]
jobs:
  validate:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build
        run: build_nevm.bat
      - name: Run PR CHECK Gates
        run: nevm_validate.exe --mode=pr_check
        continue-on-error: false
```

```yaml
# .github/workflows/nightly.yml
name: Nightly Validation
on:
  schedule:
    - cron: '0 2 * * *'
  push:
    branches: [main]
jobs:
  validate:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build
        run: build_nevm.bat
      - name: Run NIGHTLY Gates
        run: nevm_validate.exe --mode=nightly
      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: nightly-results
          path: failure_artifacts/
```

### Azure DevOps

```yaml
# azure-pipelines.yml
stages:
- stage: PR_Check
  condition: eq(variables['Build.Reason'], 'PullRequest')
  jobs:
  - job: Validate
    steps:
    - script: build_nevm.bat
    - script: nevm_validate.exe --mode=pr_check

- stage: Nightly
  condition: or(eq(variables['Build.Reason'], 'Schedule'), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - job: Validate
    timeoutInMinutes: 120
    steps:
    - script: build_nevm.bat
    - script: nevm_validate.exe --mode=nightly
    - publish: failure_artifacts/
      artifact: nightly-results
```

## Performance Budgets

### PR CHECK Budgets

```cpp
PerformanceBudget pr_check = {
    .tok_s_min = 30.0f,
    .memory_max_mb = 10240.0f,
    .latency_p99_ms_max = 120.0f,
    .regression_threshold_pct = -10.0f  // More lenient for PR
};
```

### NIGHTLY Budgets

```cpp
PerformanceBudget nightly = {
    .tok_s_min = 35.0f,
    .memory_max_mb = 8192.0f,
    .latency_p99_ms_max = 100.0f,
    .regression_threshold_pct = -5.0f  // Stricter for nightly
};
```

## Failure Handling

### PR CHECK Failures

1. Immediate failure notification
2. PR blocked from merge
3. Console output shows first failure only
4. No artifact collection (fast feedback)

### NIGHTLY Failures

1. Complete all gates before failing
2. Collect failure artifacts
3. Upload to artifact storage
4. Send Slack notification
5. Create GitHub issue on regression

## Historical Tracking

NIGHTLY results are tracked in:
- `performance_trends.json` - JSON format for tooling
- `performance_trends.csv` - CSV for spreadsheet import
- Grafana dashboard (optional)

## Notes

- PR CHECK focuses on correctness, not performance
- NIGHTLY validates performance and stability
- Extended stress test only runs in NIGHTLY
- Golden output tests only run in NIGHTLY (deterministic mode)
- Failure artifacts only collected in NIGHTLY
