# RawrXD Validation Framework

**Version:** 15.0.0-dev  
**Status:** Milestone 1 - Validation Framework Implementation

---

## Overview

Automated validation for every layer of the RawrXD runtime.

---

## Test Organization

```
tests/
├── cpu/           - CPU kernel tests (AVX2, AVX512, Scalar)
├── gpu/           - GPU tests (Vulkan, WebGPU)
├── tokenizer/     - Tokenizer tests (BPE, SentencePiece)
├── gguf/          - GGUF format tests
├── kernels/       - Kernel tests (RMSNorm, Softmax, etc.)
├── transformer/   - Transformer layer tests
├── sampler/       - Sampling tests
└── integration/   - End-to-end tests
```

---

## Running Tests

```bash
# Run all tests
.\run_validation.bat

# Run specific category
.\run_validation.bat cpu
.\run_validation.bat gpu

# Generate report
.\run_validation.bat --report
```

---

## Milestone 1: Validation Framework

### CPU Tests
- [ ] AVX2 kernel accuracy
- [ ] AVX512 kernel accuracy  
- [ ] Scalar fallback correctness
- [ ] Numerical parity checks

### GPU Tests
- [ ] Vulkan compute shaders
- [ ] WebGPU kernels
- [ ] CPU/GPU parity

### Tokenizer Tests
- [ ] BPE tokenization
- [ ] SentencePiece
- [ ] Special token handling

### GGUF Tests
- [ ] Magic validation
- [ ] Tensor loading
- [ ] Quantization support

### Kernel Tests
- [ ] RMSNorm
- [ ] Softmax
- [ ] SiLU/GELU
- [ ] RoPE
- [ ] Attention

### Transformer Tests
- [ ] Layer correctness
- [ ] Hidden states
- [ ] Logit verification

### Sampler Tests
- [ ] Temperature
- [ ] Top-k
- [ ] Top-p

### Integration Tests
- [ ] End-to-end inference
- [ ] Model loading
- [ ] Chat completion

---

## Milestone 2: Golden Reference

```
reference/
├── tinyllama/
│   ├── logits/
│   ├── hidden/
│   ├── tokens/
│   └── hashes.sha256
├── phi3/
└── ministral/
```

Regression tests compare against these automatically.

---

## CI/CD

Tests run on every push to main.

See `.github/workflows/ci-cd.yml`
