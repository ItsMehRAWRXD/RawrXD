# RawrXD Inference Validation - Quick Start

**Date:** 2026-07-15  
**Status:** Framework Ready

## Overview

The inference validation framework is designed to verify that RawrXD produces identical outputs to reference implementations (llama.cpp) for:
- Tokenizer (BPE encoding/decoding)
- Embeddings
- Layer outputs (RMSNorm, Attention, FFN)
- Final logits
- Sampling (deterministic)

## Framework Components

```
tests/inference_validation/
├── harness/
│   ├── reference_loader.cpp    # Load reference binary data
│   ├── tensor_compare.cpp      # Numerical comparison
│   └── validation_runner.cpp   # Main orchestrator
├── fixtures/
│   └── prompts.json            # Test prompts
├── logits/
│   └── logits_compare.hpp      # Logit validation
├── sampling/
│   └── deterministic_rng.hpp   # RNG validation
└── scripts/
    └── generate_reference_data.py  # Generate from llama.cpp
```

## Quick Validation (No Model Required)

### 1. Tokenizer Validation

```cpp
// Test BPE encoding matches reference
std::string prompt = "Hello, world!";
std::vector<int> tokens = tokenizer.encode(prompt);
// Compare against reference tokens
```

### 2. Tensor Operations

```cpp
// Validate individual kernels
validate_rmsnorm(input, expected_output);
validate_softmax(scores, expected_probs);
validate_matmul(A, B, expected_C);
```

### 3. Numerical Tolerance

| Operation | Tolerance | Notes |
|-----------|-----------|-------|
| RMSNorm | 1e-5 | Per-element absolute |
| Softmax | 1e-4 | Probability distribution |
| MatMul | 1e-3 | Accumulation error |
| Logits | 1e-2 | Final layer variance |

## Running Validation

### Build
```bash
cd tests/inference_validation/harness
g++ -std=c++17 -O2 -o validation_runner.exe \
    validation_runner.cpp \
    reference_loader.cpp \
    tensor_compare.cpp
```

### Run
```bash
./validation_runner.exe \
    --model path/to/model.gguf \
    --reference llama.cpp \
    --logits \
    --sampling \
    --tolerance 1e-5
```

## Status

- ✅ Framework: IMPLEMENTED
- ✅ Tensor comparison: READY
- ✅ Reference loader: READY
- ⏳ Model integration: PENDING
- ⏳ Reference data generation: PENDING

## Next Steps

1. Generate reference data from llama.cpp
2. Connect to RawrXD runtime
3. Run layer-by-layer comparison
4. Validate end-to-end inference

## Notes

The validation framework is production-ready. Connection to the runtime requires the model loading pipeline to be fully integrated.
