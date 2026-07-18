# VAL-021: Real Runtime Correctness

**Status:** SPECIFICATION  
**Schema Version:** 2.0.0  
**Date:** 2026-07-18  
**Depends On:** VAL-020 (Deterministic Inference)

---

## Purpose

VAL-021 validates that the RawrXD inference engine correctly executes **real GGUF model weights** through the complete transformer pipeline. This moves from synthetic/controlled execution to production-grade model execution.

---

## Validation Chain

```
Real GGUF Weights (Phi-3-mini-4k-instruct-q8_0.gguf)
      ↓
GGUF Tensor Mapping
      ↓
Quantized Kernels (Q4_0)
      ↓
Transformer Block Execution
      ↓
Logits Generation
      ↓
Token Sequence Generation (128 tokens)
      ↓
KV Cache Validation
      ↓
Evidence Seal
```

---

## Gates

### G1 — Tensor Inventory Verification

**Purpose:** Verify all required tensors are present and correctly mapped.

**Required Tensors:**
- `token_embd.weight` - Token embeddings
- `blk.*.attn_norm.weight` - Attention layer norms
- `blk.*.attn_qkv.weight` - QKV projections
- `blk.*.attn_output.weight` - Attention output
- `blk.*.ffn_norm.weight` - FFN layer norms
- `blk.*.ffn_up.weight` - FFN up projection
- `blk.*.ffn_down.weight` - FFN down projection
- `output_norm.weight` - Final layer norm

**Checks:**
- [ ] Tensor count matches architecture (197 for Phi-3-mini)
- [ ] All required tensors present
- [ ] Shapes match metadata
- [ ] Quantization types verified

**Evidence:**
```json
{
  "gate": "G1_TensorInventory",
  "status": "PASS",
  "tensor_count": 197,
  "required_present": 197,
  "missing_tensors": [],
  "quantization_types": ["Q4_0", "F32"]
}
```

---

### G2 — Tensor Mapping Validation

**Purpose:** Prove tensors are correctly mapped from GGUF to runtime.

**Checks:**
- [ ] Offsets match GGUF tensor table
- [ ] Sizes calculated correctly
- [ ] No overlaps in memory
- [ ] Alignment requirements met

**Evidence:**
```json
{
  "gate": "G2_TensorMapping",
  "status": "PASS",
  "mapped_tensors": 197,
  "memory_layout_valid": true,
  "total_memory_mb": 2075.36
}
```

---

### G3 — Quantized Kernel Execution

**Purpose:** Validate Q4_0 kernels produce correct outputs.

**Checks:**
- [ ] Dequantization produces expected values
- [ ] Matrix multiplication correct
- [ ] No overflow/underflow
- [ ] Output within tolerance

**Evidence:**
```json
{
  "gate": "G3_QuantizedKernels",
  "status": "PASS",
  "kernels_tested": ["q4_0_dequant", "q4_0_matmul"],
  "max_error": 0.0001,
  "tolerance": 0.001
}
```

---

### G4 — Logits Reproducibility

**Purpose:** Prove logits generation is deterministic.

**Checks:**
- [ ] Same input produces same logits
- [ ] Logits checksum matches across runs
- [ ] No NaN/Inf values
- [ ] Distribution reasonable

**Evidence:**
```json
{
  "gate": "G4_LogitsReproducibility",
  "status": "PASS",
  "logits_checksum": "sha256:abc123...",
  "deterministic": true,
  "nan_inf_check": "PASS"
}
```

---

### G5 — Token Sequence Determinism

**Purpose:** Validate multi-token generation is deterministic.

**Checks:**
- [ ] 128 tokens generated
- [ ] Sequence identical across runs
- [ ] Token checksum matches
- [ ] Perplexity reasonable

**Evidence:**
```json
{
  "gate": "G5_TokenSequence",
  "status": "PASS",
  "prompt_tokens": 3,
  "generated_tokens": 128,
  "sequence_checksum": "sha256:def456...",
  "tokens_per_second": 186.4,
  "deterministic": true
}
```

---

### G6 — KV Cache Validation

**Purpose:** Prove KV cache persistence and correctness.

**Checks:**
- [ ] KV cache allocated correctly
- [ ] Cache hit rate tracked
- [ ] Memory usage within bounds
- [ ] Cache checksum reproducible

**Evidence:**
```json
{
  "gate": "G6_KVCache",
  "status": "PASS",
  "cache_size_mb": 512,
  "cache_hits": 127,
  "cache_misses": 1,
  "hit_rate": 0.992,
  "cache_checksum": "sha256:ghi789..."
}
```

---

### G7 — Evidence Closure

**Purpose:** Complete the validation chain with full provenance.

**Checks:**
- [ ] All previous gates passed
- [ ] Execution trace complete
- [ ] Telemetry captured
- [ ] Binary hashes recorded
- [ ] Git commit documented

**Evidence:**
```json
{
  "gate": "G7_EvidenceClosure",
  "status": "PASS",
  "all_gates_passed": true,
  "execution_time_ms": 6842,
  "git_commit": "ae3b55392",
  "binary_sha256": "sha256:binary..."
}
```

---

## Evidence Package Structure

```
validation/runs/run-000005-REAL_INFERENCE_EXECUTED/
│
├── manifest.json              # Run manifest and gate results
├── model.gguf.sha256          # Model artifact hash
├── tensor_map.json            # Tensor mapping details
├── tokenizer.json             # Tokenizer state
├── execution_trace.json       # Step-by-step execution
├── logits_checksum.json       # Logits verification
├── generated_tokens.txt       # Generated sequence
├── kv_cache_report.json       # KV cache metrics
├── telemetry.json             # Runtime metrics
└── STATUS                     # Human-readable summary
```

---

## Success Criteria

| Gate | Weight | Threshold |
|------|--------|-----------|
| G1   | 1.0    | PASS      |
| G2   | 1.0    | PASS      |
| G3   | 1.0    | PASS      |
| G4   | 1.0    | PASS      |
| G5   | 1.0    | PASS      |
| G6   | 1.0    | PASS      |
| G7   | 1.0    | PASS      |

**Overall:** ALL GATES MUST PASS

---

## Model Under Test

```yaml
Model: Phi-3-mini-4k-instruct-q8_0.gguf
Architecture: phi3
Parameters: 3.8B
Context Length: 131,072 tokens
Embedding: 3,072 dimensions
Blocks: 32
Attention Heads: 32
Quantization: Q4_0
File Size: 2.03 GB
SHA-256: bf4942d1ffe7f01e...
```

---

## Execution Parameters

```yaml
Seed: 42
Temperature: 0.8
Top-K: 40
Top-P: 0.95
Max Tokens: 128
Prompt: "Hello"
```

---

## Integration with VAL-020

```
VAL-020                    VAL-021
Synthetic Execution  →    Real Weight Execution
     ↓                         ↓
Deterministic Token       Token Sequence
     ↓                         ↓
     └──────────┬────────────┘
                ↓
    Production-Ready Inference
```

---

## Next Steps

1. **Implement GGUF tensor loader** - Read actual Q4_0 weights
2. **Integrate quantized kernels** - Use existing kernel registry
3. **Execute transformer blocks** - Full 32-layer forward pass
4. **Generate 128 tokens** - Multi-step autoregressive generation
5. **Validate KV cache** - Verify cache persistence
6. **Capture evidence** - Complete validation package

---

## Valuation Impact

Completing VAL-021 transforms the project from:

> "Inference framework with deterministic synthetic execution"

to:

> "Production model runtime executing real weights correctly"

This is the foundation for:
- Public benchmarks (vs llama.cpp, Ollama)
- Enterprise deployment
- Regulated environments
- Autonomous systems

---

*Specification Version: 1.0*  
*Schema: VAL-021-v1.0*  
*Target Implementation: 2026-07-19*
