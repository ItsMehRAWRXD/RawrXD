# RawrXD Inference Validation Framework

**Prove numerical equivalence between RawrXD and llama.cpp**

## Overview

This framework validates that RawrXD produces identical outputs to llama.cpp for every transformer layer:

- RMSNorm outputs
- Attention Q/K/V and output projections
- FFN (SwiGLU) outputs
- Final logits

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  llama.cpp      │────▶│  Reference Data  │◄────│  RawrXD Runtime │
│  (instrumented) │     │  (.bin files)    │     │  (with hooks)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  validation_     │
                        │  runner          │
                        │  (AVX-512 compare│
                        └──────────────────┘
```

## Quick Start

### 1. Generate Reference Data

```bash
# From llama.cpp directory
git apply patches/rawrxd_validation_instrumentation.patch
mkdir build && cd build
cmake .. -DRAWRXD_VALIDATION_MODE=ON
cmake --build . -j

./bin/main -m model.gguf -p "Hello" -n 10 --seed 42 --temp 0.0
# Creates: rawrxd_ref_<model>.bin
```

### 2. Build Validation Framework

```bash
cd tests/inference_validation
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

### 3. Run Smoke Test

```bash
./Release/validation_smoke
```

### 4. Compare RawrXD Output

```bash
# Build RawrXD with validation
../../build_with_validation.bat

# Run RawrXD (generates rawrxd_output.bin)
./build_validation/Release/rawrxd.exe --model model.gguf --prompt "Hello"

# Compare
./Release/validation_runner \
    --reference rawrxd_ref_model.bin \
    --actual rawrxd_output.bin
```

## File Structure

```
inference_validation/
├── harness/
│   ├── tensor_compare.hpp/cpp      # AVX-512 tensor comparison
│   ├── reference_loader.hpp/cpp   # Binary reference file loader
│   ├── runtime_hooks.hpp            # Header-only validation macros
│   └── validation_runner.cpp        # Main comparison tool
├── scripts/
│   └── generate_reference_data.py   # Automated llama.cpp instrumentation
├── patches/
│   └── llama.cpp/                   # llama.cpp instrumentation patch
├── fixtures/                        # Reference data storage
├── CMakeLists.txt                   # Build configuration
├── test_validation_smoke.cpp        # Sanity check test
└── README.md                        # This file
```

## Binary Format

Reference files use a simple binary format:

```
Header (8 bytes):
  - Magic:    0x52414452 ("RADR")
  - Version:  1

Records (variable):
  - Layer index:    int32
  - Name length:    uint16
  - Name:           char[]
  - Num dimensions: int32
  - Shape:          int32[]
  - Num elements:   uint64
  - Data:           float32[]
```

## Validation Macros

Include `runtime_hooks.hpp` in RawrXD transformer code:

```cpp
// At Forward() entry
RAWRXD_VALIDATION_INIT("rawrxd_output.bin");

// Per layer
RAWRXD_VALIDATION_DUMP_RMS_NORM(x.data(), dim, layer_idx);
RAWRXD_VALIDATION_DUMP_ATTN_OUT(x.data(), dim, layer_idx);
RAWRXD_VALIDATION_DUMP_FFN(x.data(), dim, layer_idx);

// At exit
RAWRXD_VALIDATION_DUMP_LOGITS(logits.data(), vocab_size);
RAWRXD_VALIDATION_CLOSE();
```

Macros are no-ops unless `RAWRXD_ENABLE_VALIDATION` is defined.

## Tolerance Guidelines

| Component | Absolute | Relative | Notes |
|-----------|----------|----------|-------|
| RMSNorm   | 1e-5     | 1e-4     | Very strict |
| Attention | 1e-4     | 1e-3     | Softmax variance |
| FFN       | 1e-5     | 1e-4     | Strict |
| Logits    | 1e-3     | 1e-2     | Sampling tolerant |

## API Reference

### Tensor Comparison

```cpp
TensorComparison compareTensor(
    const float* expected,
    const float* actual,
    size_t count,
    float tolerance = 1e-5f
);

TensorComparison compareTensorAVX512(
    const float* expected,
    const float* actual,
    size_t count,
    float tolerance = 1e-5f
);
```

### Reference Loader

```cpp
ReferenceLoader loader;
loader.load("reference.bin");

const TensorRecord* rec = loader.findTensor("rms_norm", 0);
// rec->data, rec->shape, rec->layer_idx
```

## Troubleshooting

### No output file generated
- Check that `RAWRXD_ENABLE_VALIDATION` is defined
- Verify file permissions in working directory
- Ensure `RAWRXD_VALIDATION_INIT` was called

### Size mismatches
- Use identical model files
- Check layer count matches
- Verify hidden dimensions

### Numerical differences
- Use same quantization (F16 vs Q4_0)
- Set identical RNG seeds
- Check attention implementation

## License

Same as RawrXD project.
