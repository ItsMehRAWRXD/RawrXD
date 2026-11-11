# RawrXD N-EVM Validation Framework - Quick Start Guide

## Installation

### Windows (Visual Studio)

```bash
cd d:\RawrXD\src\nevm
build_nevm.bat
```

### Linux/macOS (CMake)

```bash
cd /path/to/RawrXD/src/nevm
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

### Docker (Reproducible CI)

```bash
docker build -t rawrxd-nevm-validator .
docker run -v $(pwd):/workspace rawrxd-nevm-validator \
    nevm_validate /workspace/model.gguf --mode=pr_check
```

## Basic Usage

### Validate a Model

```bash
# PR CHECK (fast, parallel execution)
nevm_validate model.gguf --mode=pr_check -o report.json

# NIGHTLY (comprehensive)
nevm_validate model.gguf --mode=nightly -o nightly_report.json

# Full validation with custom settings
nevm_validate model.gguf -n 256 -m bitexact -s 12345
```

### Generate Golden Output

```bash
# Create reference output for deterministic testing
nevm_generate_golden model.gguf \
    -p "Hello world" \
    -o golden_output \
    -m bitexact \
    -n 128

# Validate against golden output
nevm_validate model.gguf --golden=golden_output --math=bitexact
```

### Check for Regressions

```bash
# Create baseline
nevm_validate model.gguf --mode=nightly -o baseline.json

# Compare against baseline
nevm_validate model.gguf --mode=nightly --baseline=baseline.json
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Nightly Validation
on:
  schedule:
    - cron: '0 2 * * *'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build
        run: |
          mkdir build && cd build
          cmake .. && make -j$(nproc)
      
      - name: Run Validation
        run: ./build/bin/nevm_validate model.gguf --mode=nightly
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: validation-results
          path: '*.json'
```

### Azure DevOps

```yaml
stages:
- stage: Validate
  jobs:
  - job: PR_Check
    condition: eq(variables['Build.Reason'], 'PullRequest')
    steps:
    - script: |
        cmake -S . -B build
        cmake --build build --parallel
    - script: ./build/bin/nevm_validate model.gguf --mode=pr_check
  
  - job: Nightly
    condition: eq(variables['Build.Reason'], 'Schedule')
    timeoutInMinutes: 120
    steps:
    - script: ./build/bin/nevm_validate model.gguf --mode=nightly
    - publish: failure_artifacts/
      artifact: nightly-results
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | SUCCESS | All gates passed |
| 1 | CORRECTNESS_FAILURE | Validation failed |
| 2 | PERFORMANCE_REGRESSION | Below threshold |
| 3 | STABILITY_FAILURE | Stress test failed |
| 4 | ENVIRONMENT_FAILURE | Setup issue |
| 5 | INVALID_MODEL | Model load failed |
| 6 | SCHEMA_MISMATCH | Version incompatibility |

## Command-Line Options

### nevm_validate

```
Usage: nevm_validate <model.gguf> [options]

Options:
  --mode <mode>             Validation mode: full|pr_check|nightly
  -n, --tokens <n>          Number of tokens (default: 128)
  -w, --warmup <n>          Warmup tokens (default: 10)
  -m, --math <mode>         Math mode: fast|reproducible|bitexact
  -s, --seed <n>            Random seed (default: 42)
  --extended                Run extended stress test
  --continue-on-failure     Continue after gate failures
  -o, --output <file>       Export JSON report
  --baseline <file>         Performance baseline for regression check
  --golden <path>           Golden output directory
  --capture-artifacts       Capture failure artifacts
  -h, --help                Show help
```

### nevm_generate_golden

```
Usage: nevm_generate_golden <model.gguf> [options]

Options:
  -p, --prompt <text>       Input prompt
  -o, --output <dir>        Output directory
  -n, --tokens <n>          Max tokens
  -m, --math <mode>         Math mode
  -s, --seed <n>            Random seed
  -t, --temp <float>        Temperature
  -d, --desc <text>         Description
```

## Troubleshooting

### Build Issues

**Windows: "Cannot find vcvars64.bat"**
- Install Visual Studio 2022 with C++ workload
- Run from "Developer Command Prompt for VS 2022"

**Linux: "jsoncpp not found"**
```bash
sudo apt-get install libjsoncpp-dev
```

**macOS: "jsoncpp not found"**
```bash
brew install jsoncpp
```

### Runtime Issues

**Exit Code 6 (Schema Mismatch)**
- Update validator to match runtime version
- Check `nevm_validation_schema.hpp` for version info

**Exit Code 2 (Performance Regression)**
- Adjust `regression_threshold_pct` in performance budget
- Check if hardware/environment changed

**Exit Code 3 (Stability Failure)**
- Check `failure_artifacts/` directory for captured state
- Review stress test logs

### Golden Output Mismatch

- Ensure `--math=bitexact` mode is used
- Verify model weights haven't changed
- Check temperature is 0.0 for deterministic results

## Performance Tips

### PR CHECK Optimization
- Use `--mode=pr_check` for parallel execution
- Runs gates in parallel batches (2-3x speedup)
- Best for CI/CD integration

### Memory Optimization
- Reduce `--tokens` for faster validation
- Use `Fast` math mode for quick checks
- Skip extended stress test with `--mode=pr_check`

### Deterministic Validation
- Always use `BitExact` math mode
- Set fixed random seed with `-s`
- Use temperature=0.0

## Support

For issues and feature requests:
- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
- Documentation: See README.md for detailed information
