# RawrXD Validation Framework Integration Guide

## Overview

This guide explains how to integrate the validation framework with RawrXD runtime
to prove numerical equivalence with llama.cpp.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  llama.cpp      │────▶│  Reference Data  │◄────│  RawrXD Runtime │
│  (instrumented) │     │  (.bin files)    │     │  (with hooks)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  Validation      │
                        │  Runner          │
                        │  (compare &     │
                        │   report)        │
                        └──────────────────┘
```

## Step 1: Generate Reference Data

### Option A: Using the Python Script (Recommended)

```bash
# Build instrumented llama.cpp and generate reference data
python scripts/generate_reference_data.py \
    --model /path/to/tinyllama.gguf \
    --prompt "Hello world" \
    --n-tokens 10
```

### Option B: Manual Build

```bash
cd f:/llama.cpp

# Apply instrumentation patch
git apply patches/rawrxd_validation_instrumentation.patch

# Build with validation mode
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DRAWRXD_VALIDATION_MODE=ON
cmake --build . -j --config Release

# Run inference to generate reference data
./bin/Release/main.exe \
    -m /path/to/model.gguf \
    -p "Hello world" \
    -n 10 \
    --seed 42 \
    --temp 0.0
```

Output: `rawrxd_ref_<model_name>.bin`

## Step 2: Integrate Hooks into RawrXD

### 2.1 Add Include

In your transformer layer implementation:

```cpp
#include "inference_validation/harness/runtime_hooks.hpp"
```

### 2.2 Initialize Validation Mode

In your inference entry point:

```cpp
void run_inference(const char* model_path, const char* prompt) {
    // Initialize validation dumping
    RAWRXD_VALIDATION_INIT("rawrxd_output.bin");
    
    // ... load model ...
    
    // Run inference
    for (int layer = 0; layer < n_layers; layer++) {
        RAWRXD_VALIDATION_SET_LAYER(layer);
        
        // RMSNorm
        rms_norm(...);
        RAWRXD_VALIDATION_DUMP_RMS_NORM(output, size, layer);
        
        // Attention
        attention(...);
        RAWRXD_VALIDATION_DUMP_ATTN_OUT(attn_out, size, layer);
        
        // FFN
        ffn(...);
        RAWRXD_VALIDATION_DUMP_FFN(ffn_out, size, layer);
    }
    
    // Final logits
    compute_logits(...);
    RAWRXD_VALIDATION_DUMP_LOGITS(logits, vocab_size);
    
    RAWRXD_VALIDATION_CLOSE();
}
```

### 2.3 Compile with Validation

Add to your build:

```bash
# MSVC
cl /DRAWRXD_ENABLE_VALIDATION ...

# GCC/Clang
g++ -DRAWRXD_ENABLE_VALIDATION ...
```

## Step 3: Run Validation Comparison

```bash
# Build validation runner
cd d:/rawrxd-ci-bootstrap/tests/inference_validation
mkdir -p build && cd build
cmake ..
make

# Run comparison
./validation_runner \
    --reference rawrxd_ref_tinyllama.bin \
    --actual rawrxd_output.bin \
    --tolerance 1e-5
```

## File Format

### Binary Reference Format

```
Header (8 bytes):
  - Magic:    0x52414452 ("RADR")
  - Version:  1

Records (variable):
  - Layer index:    int32
  - Name length:    uint16
  - Name:           char[name_len]
  - Num dimensions: int32
  - Shape:          int32[n_dims]
  - Num elements:   uint64
  - Data:           float32[n_elements]
```

## Tolerance Guidelines

| Component | Absolute Tolerance | Relative Tolerance |
|-----------|-------------------|-------------------|
| RMSNorm   | 1e-5              | 1e-4              |
| Attention | 1e-4              | 1e-3              |
| FFN       | 1e-5              | 1e-4              |
| Logits    | 1e-3              | 1e-2              |

Higher tolerances for attention due to softmax numerical differences.

## CI/CD Integration

```yaml
# .github/workflows/validation.yml
name: Numerical Validation

on: [push, pull_request]

jobs:
  validate:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Generate Reference Data
        run: |
          python scripts/generate_reference_data.py \
            --model models/tinyllama.gguf \
            --skip-build
      
      - name: Build RawrXD with Validation
        run: cmake --build build --config Release
        
      - name: Run RawrXD Inference
        run: ./build/Release/rawrxd.exe --validate
        
      - name: Compare Results
        run: |
          ./validation_runner \
            --reference fixtures/tinyllama_reference.bin \
            --actual rawrxd_output.bin
```

## Troubleshooting

### Issue: Reference file not generated

- Check that `RAWRXD_VALIDATION_MODE` is defined during llama.cpp build
- Verify the model loads successfully
- Check file permissions in working directory

### Issue: Size mismatches

- Ensure both implementations use same model dimensions
- Check that layer count matches
- Verify hidden size and head dimensions

### Issue: Numerical differences

- Check quantization format (F16 vs Q4_0 etc.)
- Verify same RNG seed for sampling
- Ensure same attention implementation (flash vs standard)

## Next Steps

1. ✅ Validation framework complete
2. ✅ Reference data generator ready
3. ✅ Runtime hooks implemented
4. ⏳ Integrate hooks into RawrXD transformer layers
5. ⏳ Generate first reference dataset
6. ⏳ Prove numerical equivalence

## Files Summary

| File | Purpose |
|------|---------|
| `harness/tensor_compare.hpp/cpp` | AVX-512 tensor comparison |
| `harness/reference_loader.hpp/cpp` | Load .bin reference files |
| `harness/runtime_hooks.hpp` | Header-only runtime integration |
| `harness/validation_runner.cpp` | Main comparison tool |
| `scripts/generate_reference_data.py` | Automated reference generation |
| `patches/rawrxd_validation_instrumentation.patch` | llama.cpp instrumentation |
