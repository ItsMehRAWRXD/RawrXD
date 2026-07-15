# RawrXD Validation Harness

Complete validation suite for the RawrXD Sovereign Runtime. Compares reference implementations against native optimized kernels with detailed error metrics and performance tracking.

## Quick Start

```bash
# Build the validation harness
cd src\validation
build_validate.bat

# Run basic validation (kernel tests only)
..\..\build-validation\rawrxd_validate.exe

# Run full validation with a model
..\..\build-validation\rawrxd_validate.exe -m path\to\model.gguf -o validation_report

# Show help
..\..\build-validation\rawrxd_validate.exe -h
```

## Validation Suites

### 1. Kernel Validation
- **RMSNorm**: Reference scalar vs AVX2 implementation
- **Softmax**: Numerical accuracy verification
- **SiLU/GELU**: Activation function correctness
- **Q4_0/Q8_0/Q4_K/Q6_K**: Quantized matrix-vector multiplication
- **Error Metrics**: max_abs, max_rel, mean_abs, mean_rel, RMSE

### 2. GGUF Validation
- Magic number verification
- Version compatibility check
- Tensor enumeration and integrity
- Metadata extraction
- Offset alignment validation

### 3. Stress Validation
- Memory allocator stress (10K allocations)
- Load/unload cycles (100 iterations)
- Inference stress (1000 iterations)
- Threading primitive stress

## Error Tolerances

| Kernel Type | Max Abs Error | Mean Abs Error | Speedup |
|-------------|---------------|----------------|---------|
| FP32 (RMSNorm, Softmax) | < 1e-4 | < 1e-5 | > 3x |
| Quantized (Q4_0, Q4_K) | < 0.1 | < 0.01 | > 2x |
| Quantized (Q8_0, Q6_K) | < 0.05 | < 0.005 | > 2x |

## Output Formats

### Console Output
```
╔════════════════════════════════════════════════════════════════╗
║                 VALIDATION REPORT SUMMARY                      ║
╠════════════════════════════════════════════════════════════════╣
║ Timestamp: 2026-07-15 10:30:45                                ║
║ Version:   1.0.0                                              ║
║ CPU:       x86_64 (AVX2 supported)                            ║
╠════════════════════════════════════════════════════════════════╣
║ Total Tests:    127                                           ║
║ Passed:        127  ✓                                         ║
║ Failed:          0                                            ║
║ Skipped:         3  ⊘                                         ║
║ Pass Rate:    100.0%                                          ║
║ Time:        2456.78 ms                                       ║
╠════════════════════════════════════════════════════════════════╣
║ Status: ✓ ALL TESTS PASSED                                    ║
╚════════════════════════════════════════════════════════════════╝
```

### JSON Report (`validation_report.json`)
```json
{
  "timestamp": "2026-07-15 10:30:45",
  "rawrxd_version": "1.0.0",
  "cpu_info": "x86_64 (AVX2 supported)",
  "summary": {
    "total_tests": 127,
    "passed_tests": 127,
    "failed_tests": 0,
    "skipped_tests": 3,
    "pass_rate": 100.0,
    "total_time_ms": 2456.78
  },
  "suites": [...]
}
```

### HTML Report (`validation_report.html`)
- Visual dashboard with charts
- Drill-down test details
- Performance metrics
- Exportable for CI/CD

## CI/CD Integration

```yaml
# .github/workflows/validate.yml
name: Validation
on: [push, pull_request]
jobs:
  validate:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build
        run: src\validation\build_validate.bat
      - name: Validate
        run: build-validation\rawrxd_validate.exe -m test_model.gguf -o report
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: validation-report
          path: report.*
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | One or more tests failed |
| 2 | Initialization error |

## Adding New Tests

```c
// In rawrxd_validate.c or appropriate module
static rawrxd_test_result test_my_feature(void) {
    printf("  [TEST] My feature... ");
    
    // Setup
    // Run test
    // Check results
    
    if (passed) {
        printf("PASS\n");
        return RAWRXD_TEST_PASS;
    } else {
        printf("FAIL (reason)\n");
        return RAWRXD_TEST_FAIL;
    }
}
```

## Performance Baselines

Reference performance targets on AMD Ryzen 9 7950X:

| Operation | Size | Reference | Optimized | Speedup |
|-----------|------|-----------|-----------|---------|
| RMSNorm | 4096 | 0.5 ms | 0.08 ms | 6.25x |
| Q4_0 MatVec | 4096x4096 | 12 ms | 3 ms | 4x |
| Q8_0 MatVec | 4096x4096 | 10 ms | 2 ms | 5x |
| Softmax | 32000 | 0.8 ms | 0.2 ms | 4x |

## Troubleshooting

### "Cannot open model file"
- Verify model path is correct
- Ensure model is a valid GGUF file
- Check file permissions

### "Kernel validation failed"
- Check CPU supports AVX2
- Verify core library is built correctly
- Review error metrics in verbose mode (-v)

### "Memory allocation failed"
- Reduce test sizes
- Close other applications
- Check available system memory

## License

Part of RawrXD Sovereign Runtime - See main LICENSE file
