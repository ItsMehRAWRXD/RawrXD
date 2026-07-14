# Truth Gate 003 — Real Inference Validation

**Status**: Planning  
**Target**: Generate tokens from real GGUF model with numerical validation  
**Reference**: llama.cpp output comparison

---

## Overview

Truth Gate 003 is the critical validation milestone where RawrXD proves it can:
1. Load a real GGUF model (tinyllama-1.1b or phi-3-mini)
2. Execute complete transformer inference
3. Generate coherent tokens
4. Match llama.cpp reference outputs numerically

---

## Phase Breakdown

### Phase 1: Complete Quantization Support

**Goal**: All quantization types dequantize correctly with reference validation.

| Type | Priority | Status |
|------|----------|--------|
| Q4_0 | P0 | Structure done, needs real validation |
| Q4_K | P0 | Structure defined, implementation pending |
| Q4_K_M | P0 | Depends on Q4_K |
| Q5_K | P1 | Future work |
| Q6_K | P1 | Future work |
| Q8_0 | P1 | Future work |

**Validation Method**:
```
GGUF tensor blocks
      ↓
RawrXD dequantizer
      ↓
FP32 values
      ↓
Compare with llama.cpp dequant output
      ↓
max_abs_error < 0.001
```

---

### Phase 2: Transformer Block Implementation

**Goal**: One complete transformer layer executes correctly.

**Required tensors** (per layer):
```
blk.{N}.attn_norm.weight      [hidden_dim]
blk.{N}.attn_q.weight         [hidden_dim, hidden_dim]
blk.{N}.attn_k.weight         [hidden_dim, hidden_dim]  
blk.{N}.attn_v.weight         [hidden_dim, hidden_dim]
blk.{N}.attn_output.weight    [hidden_dim, hidden_dim]
blk.{N}.ffn_norm.weight       [hidden_dim]
blk.{N}.ffn_gate.weight       [ffn_dim, hidden_dim]
blk.{N}.ffn_up.weight         [ffn_dim, hidden_dim]
blk.{N}.ffn_down.weight       [hidden_dim, ffn_dim]
```

**Execution order**:
```
Input: x [batch, seq_len, hidden_dim]

# Self-Attention
normed = RMSNorm(x, attn_norm.weight)
q = normed @ attn_q.weight
k = normed @ attn_k.weight  
v = normed @ attn_v.weight
q, k = apply_RoPE(q, k, position_ids)
attn_weights = softmax(q @ k.T / sqrt(head_dim) + mask)
attn_out = attn_weights @ v
attn_out = attn_out @ attn_output.weight
x = x + attn_out  # Residual

# FFN
normed = RMSNorm(x, ffn_norm.weight)
gate = normed @ ffn_gate.weight
up = normed @ ffn_up.weight
ffn_out = SwiGLU(gate, up)  # gate * sigmoid(gate) * up
ffn_out = ffn_out @ ffn_down.weight
x = x + ffn_out  # Residual

Output: x
```

---

### Phase 3: KV Cache Implementation

**Goal**: Autoregressive generation with efficient memory reuse.

**Structure**:
```c
typedef struct {
    float *k_cache;  // [max_seq_len, n_kv_heads, head_dim]
    float *v_cache;  // [max_seq_len, n_kv_heads, head_dim]
    int cache_pos;   // Current position in cache
    int max_seq_len;
} kv_cache_t;
```

**Operations**:
- `kv_cache_init()`: Allocate cache for max context length
- `kv_cache_update()`: Store new K,V at current position
- `kv_cache_query()`: Retrieve all cached K,V up to current position

---

### Phase 4: Tokenizer Integration

**Goal**: Convert text to token IDs and back.

**Options**:
1. **BPE** (GPT-2 style) - tinyllama uses this
2. **SentencePiece** - Llama 2/3 uses this
3. **TikToken** - GPT-4 style

**Minimal implementation**:
- Load tokenizer vocabulary from GGUF metadata
- `encode(text) -> token_ids[]`
- `decode(token_ids[]) -> text`

---

### Phase 5: Sampling

**Goal**: Convert logits to token selection.

**Strategies** (in order of complexity):
1. **Greedy**: `argmax(logits)`
2. **Temperature**: `softmax(logits / temperature)`
3. **Top-K**: Sample from K most likely tokens
4. **Top-P (nucleus)**: Sample from smallest set where sum(p) >= P

---

### Phase 6: End-to-End Integration

**Goal**: Complete inference pipeline.

```
text_prompt = "The capital of France is"
      ↓
tokenizer.encode()
      ↓
token_ids = [1, 392, 3042, 310, 590, 338]  # "The capital..."
      ↓
embedding_lookup(token_ids)
      ↓
embeddings [seq_len, hidden_dim]
      ↓
For layer in 0..N-1:
  transformer_block(embeddings, layer_weights, kv_cache)
      ↓
final_norm
      ↓
lm_head @ output.weight
      ↓
logits [vocab_size]
      ↓
sampler.sample(logits, temperature=0.8, top_k=40)
      ↓
next_token_id
      ↓
Append to token_ids
      ↓
Repeat until EOS or max_tokens
      ↓
tokenizer.decode(generated_ids)
      ↓
output_text = " Paris"
```

---

### Phase 7: Reference Validation

**Goal**: Numerical agreement with llama.cpp.

**Test prompt**: `"The capital of France is"`

**Validation points**:

1. **Embedding lookup**:
   ```
   RawrXD embedding[0][0:5] = [0.0123, -0.0456, 0.0789, ...]
   llama.cpp embedding[0][0:5] = [0.0123, -0.0456, 0.0789, ...]
   ```

2. **Post-attention output** (Layer 0):
   ```
   RawrXD attn_out[0][0:5] = [0.0012, -0.0034, ...]
   llama.cpp attn_out[0][0:5] = [0.0012, -0.0034, ...]
   max_abs_error < 0.001
   ```

3. **Final logits**:
   ```
   RawrXD logits[top_token] = 15.234
   llama.cpp logits[top_token] = 15.235
   relative_error < 0.1%
   ```

4. **Generated token**:
   ```
   RawrXD next_token = 7392  # "Paris"
   llama.cpp next_token = 7392
   match: True
   ```

---

## Implementation Order

### Week 1: Quantization & Reference Setup
- [ ] Download tinyllama-1.1b.Q4_0.gguf
- [ ] Build llama.cpp with logging hooks
- [ ] Implement Q4_K dequantization
- [ ] Create reference comparison harness

### Week 2: Transformer Core
- [ ] Implement attention mechanism
- [ ] Implement KV cache
- [ ] Implement SwiGLU FFN
- [ ] Single-layer execution test

### Week 3: Multi-Layer & Tokenizer
- [ ] Multi-layer loop
- [ ] Tokenizer integration (BPE)
- [ ] Sampling implementation
- [ ] End-to-end pipeline

### Week 4: Validation & Polish
- [ ] Numerical comparison tool
- [ ] Fix discrepancies
- [ ] Performance benchmarking
- [ ] Documentation

---

## Success Criteria

```python
def truth_gate_003_pass():
    model = load_gguf("tinyllama-1.1b.Q4_0.gguf")
    
    # Model loads completely
    assert model.tensor_coverage == 100%
    assert model.missing_tensors == 0
    
    # Inference executes
    prompt = "The capital of France is"
    rawrxd_output = rawrxd_generate(prompt, max_tokens=5)
    llama_output = llama_cpp_generate(prompt, max_tokens=5)
    
    # Outputs match
    assert rawrxd_output == llama_output  # " Paris"
    
    # Logits match
    rawrxd_logits = rawrxd_get_logits(prompt)
    llama_logits = llama_cpp_get_logits(prompt)
    assert max_abs_error(rawrxd_logits, llama_logits) < 0.01
    
    # Performance measurable
    assert rawrxd_metrics.ttft < 1000  # ms
    assert rawrxd_metrics.tps > 10     # tokens/sec
    
    return True
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Q4_K complexity | Start with Q4_0 (tinyllama), validate numerics first |
| Tokenizer mismatch | Use GGUF embedded vocab, compare token IDs |
| Numerical drift | Use f64 for intermediate accumulators |
| Memory constraints | Implement KV cache quantization (Q8) if needed |
| llama.cpp version | Pin to specific commit, document version |

---

**Next Action**: Download tinyllama-1.1b.Q4_0.gguf and begin Phase 1
