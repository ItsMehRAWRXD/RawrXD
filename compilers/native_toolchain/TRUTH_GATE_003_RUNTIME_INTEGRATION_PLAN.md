# Truth Gate 003: Runtime Integration Plan

**Status:** IN PROGRESS  
**Goal:** Prove RawrXD can load a real GGUF model, execute inference, and produce validated tokens  
**Target Model:** `tinyllama-1.1b.Q4_0.gguf`  
**Reference:** llama.cpp b1559

---

## Current Stack (Ready to Integrate)

```
┌─────────────────────────────────────────────────────────┐
│  Phase 7C: Predictive Memory Intelligence (Framework)  │
│  ├─ SequenceLogger     ✅                                 │
│  ├─ PatternMiner     ✅                                 │
│  ├─ PolicyRefinement ✅                                 │
│  └─ OnlineAdaptation ✅                                 │
├─────────────────────────────────────────────────────────┤
│  Phase 8.1: Sovereign Runtime           ✅ BUILT        │
│  ├─ GGUF Tensor Binding                                 │
│  ├─ Tokenizer Bridge                                    │
│  ├─ KV Cache Runtime                                    │
│  └─ Kernel Execution                                    │
├─────────────────────────────────────────────────────────┤
│  Phase 8.2: RawRamXD Fabric             ✅ BUILT        │
│  ├─ VRAM Residency                                      │
│  ├─ RAM Spill                                           │
│  ├─ Predictive Prefetch                                 │
│  └─ Tensor Migration                                    │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
                    ⏳ TRUTH GATE 003
```

---

## Integration Gates

### TG3-A: Real GGUF Loads Through Sovereign Runtime
**Requirement:** Load `tinyllama-1.1b.Q4_0.gguf` and verify all tensors present

| Check | Expected | Validation |
|-------|----------|------------|
| Tensor count | GGUF metadata | Match |
| Tensor names | All present | No missing |
| Tensor shapes | Match architecture | Verify dims |
| Data types | Q4_0, F32 | Correct |

**Test:**
```cpp
SovereignModel* model = SovereignLoadModel("tinyllama-1.1b.Q4_0.gguf");
assert(model->tensor_count == expected_count);
assert(model->GetTensor("token_embd.weight") != nullptr);
```

---

### TG3-B: Fabric Manages Tensor Residency
**Requirement:** RawRamXD Fabric tracks and optimizes tensor placement

| Metric | Target |
|--------|--------|
| VRAM residency rate | >80% for active tensors |
| Prefetch hit rate | >70% |
| Spill events | <5% of accesses |
| Migration latency | <1ms per tensor |

**Test:**
```cpp
FabricTensor* ft = fabric.RegisterTensor(tensor);
fabric.SetResidency(ft, RESIDENCY_GPU);
assert(ft->current_location == LOCATION_GPU_VRAM);
```

---

### TG3-C: Transformer Layer Executes
**Requirement:** Complete forward pass through one transformer layer

Required ops:
- [ ] RMSNorm
- [ ] QKV Projection
- [ ] RoPE (Rotary Position Embedding)
- [ ] Attention (Q×K^T, Softmax, ×V)
- [ ] KV Cache append
- [ ] SwiGLU FFN
- [ ] Residual connections

**Test:**
```cpp
LayerOutput output = ExecuteTransformerLayer(input, layer_idx);
assert(output.hidden_states.shape == expected_shape);
assert(output.kv_cache_updated == true);
```

---

### TG3-D: Tokenizer Produces IDs
**Requirement:** Text → token IDs using model's tokenizer

**Test:**
```cpp
const char* prompt = "The capital of France is";
std::vector<int> tokens = tokenizer.Encode(prompt);
// tokens[0] should be <BOS> or similar
// tokens should match llama.cpp tokenization
```

---

### TG3-E: Sampler Emits Token
**Requirement:** Logits → token ID using sampling strategy

**Test:**
```cpp
int next_token = SamplerSample(logits, temperature=0.8, top_p=0.95);
assert(next_token >= 0 && next_token < vocab_size);
```

---

### TG3-F: llama.cpp Numerical Comparison
**Requirement:** RawrXD output matches llama.cpp within tolerance

| Comparison | Tolerance | Status |
|------------|-----------|--------|
| Token IDs | Exact match | ⏳ |
| Logits (first token) | <0.1% relative error | ⏳ |
| Hidden states | <1% relative error | ⏳ |

**Test:**
```cpp
// Run both implementations
int rawrxd_token = RawrXDGenerate(prompt);
int llama_token = LlamaCPPGenerate(prompt);

assert(rawrxd_token == llama_token);  // Exact match required
```

---

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUTH GATE 003                           │
│              End-to-End Integration Layer                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ TG3-A: GGUF Loader Integration                       │   │
│  │ • Load tinyllama-1.1b.Q4_0.gguf                      │   │
│  │ • Map to Sovereign TensorViews                       │   │
│  │ • Validate tensor count & shapes                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                 │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ TG3-B: Fabric Integration                            │   │
│  │ • Register tensors with RawRamXD Fabric              │   │
│  │ • Set residency policies                             │   │
│  │ • Enable prefetch for attention weights              │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                 │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ TG3-C/D/E: Transformer Execution                     │   │
│  │ • Tokenize prompt                                    │   │
│  │ • Execute embedding lookup                           │   │
│  │ • Run transformer layers                             │   │
│  │ • Sample next token                                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                 │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ TG3-F: Validation & Comparison                       │   │
│  │ • Compare tokens with llama.cpp                      │   │
│  │ • Log numerical differences                          │   │
│  │ • Generate validation report                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation Files to Create

| File | Purpose | Gates |
|------|---------|-------|
| `truth_gate_003_main.cpp` | Entry point, orchestration | All |
| `gguf_integration.cpp` | Real GGUF loading | TG3-A |
| `fabric_integration.cpp` | Fabric connection | TG3-B |
| `transformer_executor.cpp` | Layer execution | TG3-C |
| `tokenizer_integration.cpp` | Tokenizer bridge | TG3-D |
| `sampler_integration.cpp` | Token sampling | TG3-E |
| `llamacpp_validator.cpp` | Comparison harness | TG3-F |

---

## Build Command

```bash
g++ -O3 -o truth_gate_003.exe \
    truth_gate_003_main.cpp \
    gguf_integration.cpp \
    fabric_integration.cpp \
    transformer_executor.cpp \
    tokenizer_integration.cpp \
    sampler_integration.cpp \
    llamacpp_validator.cpp \
    -I src/runtime -I src/fabric \
    -L. -lsovereign_runtime -lrawramxd_fabric \
    -DTRUTH_GATE_003_BUILD
```

---

## Success Criteria

```
Truth Gate 003 PASSES when:

✅ TG3-A: tinyllama-1.1b.Q4_0.gguf loads with 0 missing tensors
✅ TG3-B: Fabric tracks >80% VRAM residency
✅ TG3-C: Transformer layer produces valid output
✅ TG3-D: Tokenizer produces expected token sequence
✅ TG3-E: Sampler emits valid token ID
✅ TG3-F: RawrXD token matches llama.cpp token for "Paris"

Output:
"The capital of France is Paris"
                    ^^^^^
                    Match!
```

---

## Current Status

| Gate | Status | Blocker |
|------|--------|---------|
| TG3-A | ⏳ Not Started | Need integration layer |
| TG3-B | ⏳ Not Started | Need fabric hooks |
| TG3-C | ⏳ Not Started | Need layer executor |
| TG3-D | ⏳ Not Started | Need tokenizer bridge |
| TG3-E | ⏳ Not Started | Need sampler |
| TG3-F | ⏳ Not Started | Need llama.cpp harness |

**Next Action:** Create `truth_gate_003_main.cpp` - the integration orchestrator
