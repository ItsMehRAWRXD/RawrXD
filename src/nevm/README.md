# RawrXD N-EVM Validation Framework

Production-grade, CI-ready validation framework for the RawrXD Neural Execution Virtual Machine (N-EVM).

## Overview

This framework provides comprehensive validation of N-EVM correctness, performance, and determinism through 11 validation gates, three math modes, and extensive stress testing.

## Quick Start

```bash
# Build the framework
build_nevm.bat

# Run PR CHECK (fast, < 5 min)
nevm_validate.exe model.gguf --mode=pr_check -o pr_report.json

# Run NIGHTLY (comprehensive, < 2 hours)
nevm_validate.exe model.gguf --mode=nightly -o nightly_report.json

# Generate golden output for deterministic testing
nevm_generate_golden.exe model.gguf -p "Hello world" -o golden_output

# Validate against golden output
nevm_validate.exe model.gguf --golden=golden_output --math=bitexact
```

## Components

### Core Validators

| Component | Purpose | File |
|-----------|---------|------|
| Unified Validator | Main orchestrator for all gates | `nevm_validate.cpp` |
| Math Mode Controller | Three-tier math mode system | `nevm_math_mode.hpp/cpp` |
| Determinism Safeguards | FP determinism controls | `nevm_determinism_safeguards.hpp/cpp` |
| KV Integrity | Cache corruption detection | `nevm_kv_integrity.hpp/cpp` |
| Execution Plan Version | Plan freshness validation | `nevm_execution_plan_version.hpp/cpp` |
| Extended Stress Test | 10,000 step soak test | `nevm_extended_stress_test.cpp` |

### CI-Ready Components

| Component | Purpose | File |
|-----------|---------|------|
| Validation Schema | Schema versioning and exit codes | `nevm_validation_schema.hpp/cpp` |
| Performance Thresholds | Regression detection | `nevm_performance_thresholds.hpp` |
| Failure Artifacts | State capture on failure | `nevm_failure_artifacts.hpp` |
| Kernel Provenance | Build tracking | `nevm_kernel_provenance.hpp` |
| Golden Output | Deterministic validation | `nevm_golden_output.hpp` |
| Golden Generator | Reference output creation | `nevm_generate_golden.cpp` |

## Validation Gates

### Gate 1: Model Load
- Verifies model loads without corruption
- Applies math mode configuration

### Gate 2: Kernel Validation
- Validates all compute kernels
- Checks numerical accuracy

### Gate 3: Transformer Validation
- Validates transformer block correctness
- Checks attention and FFN layers

### Gate 4: Logit Validation (CORRECTNESS GATE)
- Compares logits against reference
- **Blocks performance benchmarks if failed**

### Gate 5: Determinism Validation
- Validates bit-exact reproducibility
- Runs golden output tests if provided

### Gate 6: Short Inference
- Quick inference test (32 tokens)
- Measures prefill and decode throughput

### Gate 7: Long Benchmark
- Extended inference test (1024 tokens)
- Measures sustained throughput

### Gate 8: Stress Test
- 100 iteration stress test
- Checks for memory leaks and stability

### Gate 9: Extended Stress (NIGHTLY only)
- 10,000 step soak test
- Linear regression for drift detection
- Captures failure artifacts on failure

### Gate 10: Performance Budget
- Compares against baseline
- Checks regression thresholds

### Gate 11: A/B Testing
- Compares N-EVM vs baseline
- Measures speedup and memory reduction

## Math Modes

### Fast Mode
- FMA enabled, parallel reduction
- Maximum performance
- **Not deterministic**

### Reproducible Mode
- FMA disabled, tree reduction
- Deterministic across runs
- 3.2% overhead vs Fast

### BitExact Mode
- FMA disabled, sequential/Kahan summation
- Bit-exact reproducibility
- 5.3% overhead vs Fast
- **Required for golden output tests**

## CI/CD Integration

## PR CHECK Mode (Parallel Execution)

```bash
nevm_validate.exe model.gguf --mode=pr_check
```

- **Duration**: < 5 minutes (with parallel execution)
- **Gates**: 1, 2, 3, 4, 5, 11 (executed in parallel batches)
- **Exit Codes**: 0 (pass), 1, 5, 6 (block merge)
- **Speedup**: ~2-3x faster than sequential on multi-core systems

### Parallel Execution Strategy

Gates are organized into dependency batches:

1. **Batch 0** (Sequential): Load Model
2. **Batch 1** (Parallel): Kernel Validation, Transformer Validation, Logit Validation
3. **Batch 2** (Parallel): Determinism Validation, Short Inference

Dependencies ensure correctness gates complete before performance gates.

### Execution Statistics

```
=== Parallel Execution Statistics ===
Total Duration: 2450 ms
Gates Executed: 6
Gates Parallelized: 5
Parallel Speedup: 2.8x
```

### NIGHTLY Mode

```bash
nevm_validate.exe model.gguf --mode=nightly
```

- **Duration**: < 2 hours
- **Gates**: All 11 + Extended Stress
- **Exit Codes**: 0-6 (see below)
- **Artifacts**: Captured on failure

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | SUCCESS | All gates passed |
| 1 | CORRECTNESS_FAILURE | Validation failed |
| 2 | PERFORMANCE_REGRESSION | Below threshold |
| 3 | STABILITY_FAILURE | Stress test failed |
| 4 | ENVIRONMENT_FAILURE | Setup issue |
| 5 | INVALID_MODEL | Model load failed |
| 6 | SCHEMA_MISMATCH | Version incompatibility |

## Golden Output Testing

### Generate Reference Output

```bash
nevm_generate_golden.exe model.gguf \
    -p "Your test prompt here" \
    -o golden_samples/my_test \
    -m bitexact \
    -n 128 \
    -s 42
```

Creates:
- `prompt.bin` - Input prompt
- `tokens.bin` - Expected output tokens
- `tokens.txt` - Human-readable tokens
- `metadata.json` - Generation parameters
- `README.txt` - Documentation

### Validate Against Golden

```bash
nevm_validate.exe model.gguf \
    --golden=golden_samples/my_test \
    --math=bitexact
```

## Performance Regression Testing

### Create Baseline

```bash
nevm_validate.exe model.gguf --mode=nightly -o baseline.json
```

### Check for Regression

```bash
nevm_validate.exe model.gguf \
    --mode=nightly \
    --baseline=baseline.json
```

### Performance Budgets

**Conservative** (PR CHECK):
- tok/s_min: 30
- memory_max_mb: 10240
- regression_threshold_pct: -10

**Aggressive** (NIGHTLY):
- tok/s_min: 35
- memory_max_mb: 8192
- regression_threshold_pct: -5

## Failure Artifacts

When `--capture-artifacts` is enabled and a stress test fails:

```
failure_artifacts/
└── failure_20260720_143052/
    ├── model_hash.txt
    ├── plan_version.json
    ├── kv_page_state.bin
    ├── residency_timeline.json
    ├── last_tokens.txt
    ├── benchmark_context.json
    └── failure_summary.json
```

## JSON Report Format

```json
{
  "schema": {
    "version": "1.0",
    "runtime_version": "NEVM-0.4"
  },
  "config": {
    "model": "model.gguf",
    "tokens": 128,
    "math_mode": "BitExact"
  },
  "gates": [
    {
      "name": "Load Model",
      "passed": true,
      "duration_ms": 45.2,
      "metrics": {...}
    }
  ],
  "provenance": {
    "nevm_kernels": {
      "compiler_name": "MSVC",
      "compiler_version": "1940",
      "isa_path": "AVX512",
      "fma_enabled": true
    }
  },
  "performance_budget": {
    "tok_s_min": 35.0,
    "memory_max_mb": 8192.0
  },
  "summary": {
    "total_gates": 11,
    "passed": 11,
    "failed": 0,
    "all_passed": true
  },
  "timestamp": "2026-07-20T14:30:52Z"
}
```

## GitHub Actions Example

```yaml
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
      
      - name: Run NIGHTLY Validation
        run: nevm_validate.exe model.gguf --mode=nightly -o nightly_report.json
      
      - name: Upload Artifacts
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: failure-artifacts
          path: failure_artifacts/
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: nightly-report
          path: nightly_report.json
```

## Azure DevOps Example

```yaml
stages:
- stage: PR_Check
  condition: eq(variables['Build.Reason'], 'PullRequest')
  jobs:
  - job: Validate
    steps:
    - script: build_nevm.bat
    - script: nevm_validate.exe model.gguf --mode=pr_check

- stage: Nightly
  condition: or(eq(variables['Build.Reason'], 'Schedule'), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - job: Validate
    timeoutInMinutes: 120
    steps:
    - script: build_nevm.bat
    - script: nevm_validate.exe model.gguf --mode=nightly
    - publish: failure_artifacts/
      artifact: nightly-results
```

## Sample Golden Outputs

Pre-generated golden outputs are provided in `golden_samples/`:

- `simple_prompt/` - Basic "Hello world" prompt
- See `golden_samples/README.md` for details

## Building

### Requirements
- Visual Studio 2022 (14.50+)
- Windows SDK
- JSONCPP library

### Build Command
```bash
build_nevm.bat
```

### Output
- `build/nevm_validate.exe` - Unified validator
- `build/nevm_generate_golden.exe` - Golden output generator

## Troubleshooting

### Schema Mismatch (Exit Code 6)
Update validator to match runtime version.

### Performance Regression (Exit Code 2)
Check `regression_threshold_pct` in performance budget.

### Stability Failure (Exit Code 3)
Check `failure_artifacts/` for captured state.

### Golden Output Mismatch
Ensure `--math=bitexact` mode is used.

## License

Copyright (c) 2026 RawrXD Project. All rights reserved.
