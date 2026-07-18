# RawrXD Native Inference Execution Path

**Version:** 1.0  
**Date:** 2026-07-17

---

## Production-Grade Inference Claim

For a **production-grade inference claim**, every layer in this execution path must be evidenced:

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: User Interface                                     │
│  - CLI arguments parsed                                       │
│  - Prompt captured                                            │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 2: Execution ABI                                      │
│  - Entry point: mainCRTStartup                                │
│  - Stack frame initialized                                      │
│  - Arguments validated                                          │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 3: Native Backend                                     │
│  - Backend selected (CPU/GPU)                                 │
│  - Device capabilities detected                               │
│  - Memory pool initialized                                    │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 4: Kernel Registry                                    │
│  - Kernel dispatch table loaded                               │
│  - ISA features detected (AVX2/AVX512)                        │
│  - Optimal kernel selected                                    │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 5: Tensor Runtime                                     │
│  - Tensor descriptors allocated                               │
│  - Memory layout computed                                     │
│  - Stride patterns validated                                  │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 6: GGUF Reader                                        │
│  - File opened and validated                                  │
│  - Header parsed (magic, version)                             │
│  - Tensor index built                                         │
│  - Weights mapped (not copied)                                │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 7: Tokenizer                                          │
│  - Vocab loaded from tokenizer.json                           │
│  - BPE merges applied                                         │
│  - Token IDs produced                                         │
│  - Special tokens handled                                     │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 8: Embedding Lookup                                   │
│  - Token IDs → embedding indices                              │
│  - Embedding tensor accessed                                  │
│  - Embedding vectors retrieved                                │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 9: Transformer Block (×N layers)                      │
│  ├─ L9.1: RMSNorm (input)                                    │
│  ├─ L9.2: QKV Projection                                     │
│  ├─ L9.3: RoPE (position encoding)                           │
│  ├─ L9.4: Attention (Q×K^T, softmax, ×V)                   │
│  ├─ L9.5: Output Projection                                  │
│  ├─ L9.6: Residual Connection                                │
│  ├─ L9.7: RMSNorm (post-attention)                           │
│  ├─ L9.8: FFN (up-project, GELU, down-project)               │
│  └─ L9.9: Residual Connection                                │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 10: Output Head                                       │
│  - Final RMSNorm applied                                      │
│  - LM head projection (hidden → vocab)                       │
│  - Logits produced                                            │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 11: Sampler                                           │
│  - Temperature scaling applied                                │
│  - Top-k/top-p filtering                                      │
│  - Probability distribution normalized                        │
│  - Token sampled                                              │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  LAYER 12: Output                                            │
│  - Generated token ID                                         │
│  - Token decoded to text                                      │
│  - Result returned to user                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Evidence Requirements Per Layer

| Layer | Component | Evidence Required | Validation Stage |
|-------|-----------|-------------------|------------------|
| L1 | CLI | Arguments parsed, help text | VAL-018.1 |
| L2 | ABI | Entry point reached, no crash | VAL-018.1 |
| L3 | Backend | Backend selected, device detected | VAL-018.4+ |
| L4 | Kernel Registry | ISA detected, kernel selected | VAL-018.4+ |
| L5 | Tensor Runtime | Tensor allocated, layout valid | VAL-018.4+ |
| L6 | GGUF Reader | File parsed, tensors indexed | **VAL-018.2 ✅** |
| L7 | Tokenizer | Text → Token IDs | **VAL-018.3 ✅** |
| L8 | Embedding | Token IDs → Embeddings | VAL-018.4 |
| L9.1 | RMSNorm | Normalized output | VAL-018.5 |
| L9.2 | QKV | Q, K, V matrices | VAL-018.6 |
| L9.3 | RoPE | Position-encoded Q, K | VAL-018.7 |
| L9.4 | Attention | Attention weights, output | VAL-018.8 |
| L9.5 | Proj | Output projection | VAL-018.8 |
| L9.6-9.9 | Residual/FFN | FFN output, residuals | VAL-018.9 |
| L10 | Output Head | Logits produced | VAL-018.10 |
| L11 | Sampler | Token sampled | VAL-018.11 |
| L12 | Output | Generated text | VAL-018.11 |

---

## Current Evidence Status

```
Layer 1-2 (CLI/ABI):        ✅ Evidenced (binary loads)
Layer 3-5 (Backend/Runtime): ⬜ Not yet evidenced
Layer 6 (GGUF Reader):       ✅ VAL-018.2 COMPLETE
Layer 7 (Tokenizer):         ✅ VAL-018.3 COMPLETE
Layer 8 (Embedding):         ⬜ VAL-018.4 PENDING
Layer 9 (Transformer):       ⬜ VAL-018.5-018.9 PENDING
Layer 10 (Output Head):      ⬜ VAL-018.10 PENDING
Layer 11-12 (Sampler/Output): ⬜ VAL-018.11 PENDING
```

**Progress: 3 of 14 layers evidenced (21%)**

---

## What "Native Inference" Requires

### Minimum Claim (Execution Only)
- All 14 layers execute without error
- Each layer produces deterministic output
- Evidence: `"simulation": false` for each layer

### Production Claim (Correctness)
- All 14 layers execute
- Each layer output matches algorithm specification
- Golden vectors for key operations (RMSNorm, Attention, FFN)
- Numerical invariants verified

### Full Compatibility Claim
- All 14 layers execute
- Output matches reference implementation (llama.cpp)
- Tokenizer parity: same text → same token IDs
- Logits parity: same tokens → same logits (within tolerance)
- Generation parity: greedy decoding produces identical text

---

## Evidence Checklist

### For Each Layer:
- [ ] Input captured (shape, dtype, checksum)
- [ ] Execution traced (timestamp, phase)
- [ ] Output captured (shape, dtype, checksum)
- [ ] Determinism verified (re-run produces same checksum)
- [ ] Timing recorded (ms elapsed)
- [ ] Memory tracked (peak usage)

### For Correctness (VAL-019):
- [ ] Golden vectors generated
- [ ] Expected output known
- [ ] Tolerance defined
- [ ] Comparison passes

### For Compatibility (VAL-019+):
- [ ] Reference implementation identified
- [ ] Same input prepared
- [ ] Outputs compared
- [ ] Tolerance met

---

## Artifact Chain

```
Source Code
    ↓ (git commit: abc123)
Build System
    ↓ (compiler: MSVC 19.40, flags: /O2 /arch:AVX2)
Binary
    ↓ (sha256: 1234...)
Execution
    ↓ (environment: Windows 11, Ryzen 9, RTX 4090)
Evidence
    ↓ (trace.json, output.bin, checksums)
Validation Result
    (PASS / FAIL)
```

Every arrow must be evidenced for a production claim.
