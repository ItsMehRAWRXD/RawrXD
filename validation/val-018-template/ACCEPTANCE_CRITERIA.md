# VAL-018 Acceptance Criteria

**Version:** 1.0  
**Date:** 2026-07-17

---

## Universal Gates (All Stages)

Every VAL-018 validation stage MUST satisfy these criteria to be considered **PASS**:

| Gate | Requirement | Verification |
|------|-------------|------------|
| **G1** | `simulation == false` | Evidence JSON contains `"simulation": false` |
| **G2** | Exit code == 0 | Process returns 0 on success |
| **G3** | Evidence JSON written | `result/completion.json` exists and is valid JSON |
| **G4** | Execution trace present | `execution/trace.json` exists with phase entries |
| **G5** | Deterministic checksum | Same input produces same output checksum across runs |

---

## Level-Specific Criteria

### Level 1: Repeatability

**Goal:** Prove the component executes deterministically.

| Criterion | Check | Evidence |
|-----------|-------|----------|
| **L1.1** | Component loads without error | Trace shows successful initialization |
| **L1.2** | Input is processed | Trace shows input loading phase |
| **L1.3** | Output is produced | Output file exists with non-zero size |
| **L1.4** | Checksum is stable | Re-run produces identical checksum |
| **L1.5** | Execution time recorded | `timing_ms` field present |

**PASS if:** G1-G5 AND L1.1-L1.5

---

### Level 2: Correctness

**Goal:** Prove the component satisfies its algorithm specification.

| Criterion | Check | Evidence |
|-----------|-------|----------|
| **L2.1** | Output shape matches spec | Shape matches expected dimensions |
| **L2.2** | Output dtype matches spec | dtype is as specified |
| **L2.3** | Mathematical invariants hold | Invariants verified (e.g., sum, norm) |
| **L2.4** | Values in expected range | All values within [min, max] |
| **L2.5** | Edge cases handled | Boundary inputs produce expected output |

**PASS if:** Level 1 PASS AND L2.1-L2.5

---

### Level 3: Compatibility

**Goal:** Prove the component matches a reference implementation.

| Criterion | Check | Evidence |
|-----------|-------|----------|
| **L3.1** | Reference implementation identified | Name and version of reference documented |
| **L3.2** | Same input produces equivalent output | Output matches reference within tolerance |
| **L3.3** | Tokenizer compatibility | Token IDs match reference tokenizer |
| **L3.4** | Numerical tolerance met | Max absolute error < epsilon |
| **L3.5** | Cross-platform consistency | Results reproducible on different hardware |

**PASS if:** Level 2 PASS AND L3.1-L3.5

---

## Stage-Specific Criteria

### VAL-018.2: GGUF Loader

**Level 1 Criteria:**
- [ ] Opens real GGUF file without error
- [ ] Parses header (magic, version, tensor_count, metadata_kv_count)
- [ ] Enumerates all tensors
- [ ] Metadata varies correctly per model file
- [ ] Tensor offsets are valid (within file bounds)

**Level 2 Criteria:**
- [ ] Header fields match GGUF specification
- [ ] Tensor dimensions are consistent
- [ ] Metadata types are valid

**Level 3 Criteria:**
- [ ] Output matches llama.cpp gguf parsing
- [ ] Tensor offsets match reference loader

---

### VAL-018.3: Tokenizer

**Level 1 Criteria:**
- [ ] Loads tokenizer.json without error
- [ ] Parses vocabulary
- [ ] Produces deterministic token IDs
- [ ] Handles ASCII text
- [ ] Handles UTF-8/Unicode

**Level 2 Criteria:**
- [ ] Token IDs match BPE algorithm specification
- [ ] Special tokens handled correctly
- [ ] Byte-level fallback works

**Level 3 Criteria:**
- [ ] Token IDs match HuggingFace tokenizer
- [ ] Token IDs match llama.cpp tokenizer
- [ ] Same model produces identical IDs across implementations

---

### VAL-018.4: Embedding Lookup

**Level 1 Criteria:**
- [ ] Loads embedding tensor from GGUF
- [ ] Indexes embedding by token ID
- [ ] Produces deterministic output
- [ ] Output shape is [num_tokens, embedding_dim]

**Level 2 Criteria:**
- [ ] Embedding values are valid floats
- [ ] No NaN or Inf values
- [ ] Values within expected range

**Level 3 Criteria:**
- [ ] Embeddings match reference implementation
- [ ] Same token ID produces same embedding vector

---

### VAL-018.5-018.10: Transformer Components

**Level 1 Criteria:**
- [ ] Component executes without error
- [ ] Input/output shapes are correct
- [ ] Output is deterministic
- [ ] Timing is recorded

**Level 2 Criteria:**
- [ ] Mathematical properties hold (e.g., RMSNorm preserves scale)
- [ ] Numerical stability (no overflow/underflow)
- [ ] Edge cases handled

**Level 3 Criteria:**
- [ ] Output matches reference implementation
- [ ] Numerical error within tolerance
- [ ] Same weights produce same output

---

### VAL-018.11: End-to-End Inference

**Level 1 Criteria:**
- [ ] Full pipeline executes (tokenizer → embeddings → transformer → logits → sampling)
- [ ] Output is deterministic
- [ ] Generated token is valid

**Level 2 Criteria:**
- [ ] Logits are valid probability distribution
- [ ] Sampling produces expected distribution
- [ ] Attention patterns are valid

**Level 3 Criteria:**
- [ ] Generated text matches reference (greedy decoding)
- [ ] Perplexity matches reference
- [ ] Same prompt produces same output across implementations

---

## Validation Status Tracking

| Stage | Level 1 | Level 2 | Level 3 |
|-------|---------|---------|---------|
| VAL-018.2 (GGUF Loader) | ✅ PASS | ⬜ | ⬜ |
| VAL-018.3 (Tokenizer) | ✅ PASS | ⬜ | ⬜ |
| VAL-018.4 (Embedding) | ⬜ | ⬜ | ⬜ |
| VAL-018.5 (RMSNorm) | ⬜ | ⬜ | ⬜ |
| VAL-018.6 (QKV) | ⬜ | ⬜ | ⬜ |
| VAL-018.7 (RoPE) | ⬜ | ⬜ | ⬜ |
| VAL-018.8 (Attention) | ⬜ | ⬜ | ⬜ |
| VAL-018.9 (FFN) | ⬜ | ⬜ | ⬜ |
| VAL-018.10 (Transformer Block) | ⬜ | ⬜ | ⬜ |
| VAL-018.11 (Inference) | ⬜ | ⬜ | ⬜ |

---

## Reproducibility Requirements

For a validation to be considered **reproducible**, the evidence package must include:

1. **Implementation Details**
   - Git commit hash
   - Compiler version
   - Build type (Debug/Release)
   - Target architecture

2. **Environment Details**
   - OS version
   - CPU model
   - GPU model (if applicable)
   - Driver versions

3. **Artifact Hashes**
   - Input file SHA256
   - Output file SHA256
   - Trace file SHA256
   - Executable SHA256

4. **Execution Log**
   - Complete stdout/stderr capture
   - Timing information
   - Memory usage

---

## Failure Handling

If any gate fails:

1. **Record the failure** in `validation.failures` array
2. **Capture the error** message and stack trace
3. **Save partial evidence** for debugging
4. **Exit with non-zero code**
5. **Do not claim PASS**

Example failure record:

```json
{
  "validation": {
    "passed": false,
    "failures": [
      {
        "gate": "L1.4",
        "description": "Checksum not deterministic",
        "expected": "47339",
        "actual": "different_value",
        "details": "Output varies between runs"
      }
    ]
  }
}
```
