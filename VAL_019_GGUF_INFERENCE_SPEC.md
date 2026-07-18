# VAL-019: Real GGUF Inference Specification

**Status:** SPECIFICATION  
**Priority:** P0 (Next Major Milestone)  
**Target:** Q3 2026  
**Depends On:** VAL-017 (GGUF Loading), VAL-018 (Kernels)

---

## Scope Definition

VAL-019 represents the transition from **validated runtime framework** to **validated local LLM engine**.

### What This Is

End-to-end inference pipeline that:
- Loads real GGUF model files
- Executes transformer layers
- Produces actual tokens
- Runs entirely on local hardware

### What This Is NOT

- Simulation or mock inference
- Cloud API wrapper
- Partial pipeline (embedding-only, etc.)

---

## Validation Criteria

### Functional Requirements

| Component | Requirement | Validation Method |
|-----------|-------------|-------------------|
| GGUF Loading | Load 7B parameter model | VAL-017 extension |
| Tokenizer | Byte-pair encoding | Token count match |
| Embedding | Convert tokens to vectors | Shape verification |
| Attention | Multi-head self-attention | Numerical regression |
| RMSNorm | Layer normalization | VAL-018 kernels |
| FFN | Feed-forward network | Numerical regression |
| KV Cache | Key-value caching | Memory verification |
| Sampling | Temperature + top-p | Distribution test |
| Streaming | Token-by-token output | Latency measurement |

### Performance Requirements

| Metric | Target | Minimum |
|--------|--------|---------|
| Time-to-first-token | < 2s | < 5s |
| Tokens/second (7B) | > 10 t/s | > 5 t/s |
| Memory overhead | < 1.5x model size | < 2x |
| Context window | 4096 tokens | 2048 |

### Quality Requirements

| Test | Method | Pass Criteria |
|------|--------|---------------|
| Perplexity | WikiText-2 | Within 10% of reference |
| Coherence | Human eval | 3+ on 5-point scale |
| Reproducibility | Fixed seed | Identical outputs |

---

## Architecture

```
┌─────────────────────────────────────────┐
│           VAL-019 Pipeline              │
├─────────────────────────────────────────┤
│  Input: User prompt (string)           │
│     ↓                                  │
│  Tokenizer: BPE encoding               │
│     ↓                                  │
│  Embedding: token → 4096-d vector      │
│     ↓                                  │
│  ┌─────────────────────────────────┐   │
│  │ Transformer Layer (×32 for 7B) │   │
│  │  ┌───────────────────────────┐  │   │
│  │  │ Self-Attention            │  │   │
│  │  │  - Q/K/V projections      │  │   │
│  │  │  - Scaled dot-product     │  │   │
│  │  │  - Softmax (VAL-018)        │  │   │
│  │  │  - KV cache update        │  │   │
│  │  └───────────────────────────┘  │   │
│  │  ┌───────────────────────────┐  │   │
│  │  │ Feed-Forward              │  │   │
│  │  │  - Gate projection        │  │   │
│  │  │  - Up projection          │  │   │
│  │  │  - SiLU activation        │  │   │
│  │  │  - Down projection        │  │   │
│  │  └───────────────────────────┘  │   │
│  │  RMSNorm (VAL-018)                │   │
│  └─────────────────────────────────┘   │
│     ↓                                  │
│  LM Head: logits → vocabulary scores   │
│     ↓                                  │
│  Sampler: temperature + top-p        │
│     ↓                                  │
│  Output: Next token ID                 │
│     ↓                                  │
│  (Repeat until EOS or max length)      │
└─────────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 1: Foundation (Week 1-2)

- [ ] GGUF tensor loading (extend VAL-017)
- [ ] SentencePiece tokenizer integration
- [ ] Embedding lookup table
- [ ] Basic transformer loop structure

**Validation:** Load model, verify tensor shapes

### Phase 2: Attention (Week 3-4)

- [ ] Q/K/V projection matrices
- [ ] Scaled dot-product attention
- [ ] KV cache implementation
- [ ] Rotary positional embeddings (RoPE)

**Validation:** Attention output matches reference

### Phase 3: FFN + Norm (Week 5)

- [ ] SwiGLU FFN implementation
- [ ] RMSNorm integration (VAL-018)
- [ ] Residual connections

**Validation:** Layer output matches reference

### Phase 4: Sampling (Week 6)

- [ ] Temperature scaling
- [ ] Top-p (nucleus) sampling
- [ ] Repetition penalty

**Validation:** Sampling distribution correct

### Phase 5: End-to-End (Week 7-8)

- [ ] Full pipeline integration
- [ ] Streaming output
- [ ] Performance optimization
- [ ] Memory profiling

**Validation:** Generate 100 tokens, measure quality

---

## Test Model

**Primary:** TinyLlama-1.1B (GGUF)
- Small enough for rapid iteration
- Real transformer architecture
- Validated reference outputs

**Secondary:** Llama-2-7B (GGUF)
- Production target size
- Full validation suite
- Performance benchmarking

---

## Success Criteria

```
VAL-019 PASS requires:

1. Load real GGUF model
   └─ File: tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf

2. Generate coherent text
   └─ Prompt: "The capital of France is"
   └─ Output: Contains "Paris" in first 10 tokens

3. Meet performance targets
   └─ > 5 tokens/second on RX 7800 XT

4. Numerical stability
   └─ 10 runs with same seed → identical outputs

5. Memory efficiency
   └─ Peak RAM < 4GB for 1.1B model
```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| GGUF format changes | Medium | High | Pin to specific version |
| Tokenizer mismatch | Medium | High | Use reference tokenizer |
| Numerical drift | Low | Medium | Regression tests |
| Performance shortfall | Medium | High | Profile early |

---

## Dependencies

- VAL-017: GGUF loading (must be extended)
- VAL-018: Optimized kernels (must be integrated)
- External: sentencepiece or similar tokenizer

---

## Sign-off Criteria

| Role | Responsibility | Sign-off |
|------|---------------|----------|
| Inference Engineer | Core implementation | |
| Validation Engineer | Test coverage | |
| Performance Engineer | Speed targets | |
| Release Manager | Integration | |

---

**Next Step:** Create VAL-019 implementation branch and begin Phase 1
