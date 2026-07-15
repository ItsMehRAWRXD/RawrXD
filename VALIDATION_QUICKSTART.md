# RawrXD Validation Quick Start

## One-Line Quick Start

```bash
cd src\validation && build_validate.bat && run_validation.bat
```

## Full Validation with Model

```bash
cd src\validation
build_validate.bat
validate_all.bat -m ..\..\models\llama-7b.gguf
```

## What Gets Validated

### Without Model (Kernel Tests Only)
- ✓ Memory allocator (small/large, alignment, stress)
- ✓ Kernel correctness (RMSNorm, Softmax, SiLU, GELU)
- ✓ Quantized kernels (Q4_0, Q8_0, Q4_K, Q6_K)
- ✓ Threading primitives
- ✓ Math utilities

### With Model (Full Validation)
Everything above PLUS:
- ✓ GGUF format validation
- ✓ Model loading/unloading
- ✓ Tokenization
- ✓ Forward pass correctness
- ✓ Text generation
- ✓ KV cache management
- ✓ Inference performance
- ✓ Load/unload stress (100 cycles)
- ✓ Inference stress (1000 iterations)

## Output Files

```
validation-reports/
├── validation_YYYYMMDD_HHMMSS.json    # Machine-readable results
└── validation_YYYYMMDD_HHMMSS.html    # Human-readable dashboard
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed ✓ |
| 1 | Some tests failed ✗ |
| 2 | Setup/init error |

## CI/CD Integration

### GitHub Actions
```yaml
- name: Validate
  run: |
    cd src\validation
    build_validate.bat
    validate_all.bat -m models\test.gguf
```

### Azure DevOps
```yaml
steps:
- script: ci_validate.bat $(modelPath)
```

## Troubleshooting

**"Validator not found"**
→ Run `build_validate.bat` first

**"Cannot load model"**
→ Verify model path and format (must be GGUF)

**"Tests failed"**
→ Check HTML report for detailed failure info
