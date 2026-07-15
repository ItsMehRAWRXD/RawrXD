# RawrXD Validation Quickstart

Prove numerical equivalence between RawrXD and llama.cpp.

## Prerequisites

- Windows with VS2022 or compatible compiler
- Python 3.8+ for reference generation
- A GGUF model (e.g., TinyLlama)

## Step 1: Generate Reference Data from llama.cpp

```bash
# Apply instrumentation patch to llama.cpp
cd f:/llama.cpp
git apply patches/rawrxd_validation_instrumentation.patch

# Build instrumented llama.cpp
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DRAWRXD_VALIDATION_MODE=ON
cmake --build . --config Release -j

# Run inference to generate reference data
./bin/Release/main.exe \
    -m /path/to/tinyllama.gguf \
    -p "Hello world" \
    -n 10 \
    --seed 42 \
    --temp 0.0

# Output: rawrxd_ref_tinyllama.bin
```

## Step 2: Build RawrXD with Validation

```bash
cd d:/rawrxd-ci-bootstrap

# Option A: Use batch file
build_with_validation.bat

# Option B: Manual build
mkdir build_validation && cd build_validation
cmake .. -DCMAKE_BUILD_TYPE=Release -DRAWRXD_ENABLE_VALIDATION=ON
cmake --build . --config Release -j
```

## Step 3: Run RawrXD Inference

```bash
# Run RawrXD with same prompt
./build_validation/Release/rawrxd.exe \
    --model /path/to/tinyllama.gguf \
    --prompt "Hello world" \
    --tokens 10

# Output: rawrxd_output.bin (in working directory)
```

## Step 4: Compare Results

```bash
# Build validation runner
cd tests/inference_validation
mkdir build && cd build
cmake ..
cmake --build . --config Release

# Run comparison
./Release/validation_runner \
    --reference rawrxd_ref_tinyllama.bin \
    --actual rawrxd_output.bin \
    --tolerance 1e-5
```

## Expected Output

```
========== Validation Results ==========

[✓ PASS] RMSNorm_L0
  max_error=0.000001, mean_error=0.000000, mismatches=0

[✓ PASS] Attention_L0
  max_error=0.000003, mean_error=0.000001, mismatches=0

[✓ PASS] FFN_L0
  max_error=0.000002, mean_error=0.000001, mismatches=0

...

[✓ PASS] Logits
  max_error=0.000010, mean_error=0.000003, mismatches=0

========================================
Total: 33 | Passed: 33 | Failed: 0
========================================
```

## Troubleshooting

### No reference file generated
- Check that llama.cpp was built with `-DRAWRXD_VALIDATION_MODE=ON`
- Verify model loads successfully
- Check working directory permissions

### Size mismatches
- Ensure same model used for both
- Check layer count matches
- Verify hidden dimensions identical

### Numerical differences
- Use same quantization format (F16 vs Q4_0)
- Set same RNG seed
- Check attention implementation matches

## Files Reference

| File | Purpose |
|------|---------|
| `tests/inference_validation/harness/runtime_hooks.hpp` | Validation macros |
| `tests/inference_validation/harness/reference_loader.cpp` | Load .bin files |
| `tests/inference_validation/harness/tensor_compare.cpp` | AVX-512 comparison |
| `patches/llama.cpp/rawrxd_validation_instrumentation.patch` | llama.cpp patch |
| `build_with_validation.bat` | Build script |

## Binary Format

```
Header (8 bytes):
  Magic:    "RADR" (0x52414452)
  Version:  1

Record:
  Layer:      int32
  Name len:   uint16
  Name:       char[]
  N dims:     int32
  Shape:      int32[]
  N elements: uint64
  Data:       float32[]
```
