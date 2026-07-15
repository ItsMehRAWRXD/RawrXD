# Truth Gate 003 — Frozen State

**Date**: 2026-07-14  
**Status**: Phase 5 Frozen — Artifact Understanding Complete  
**Next Phase**: Behavioral Proof (TG3-G1 through TG3-G3)

---

## Frozen Capability State — Phase 5

### ✅ Proven
- Real GGUF artifact ingestion
- GGUF metadata parsing
- Tensor inventory/extraction path
- Vocabulary extraction path
- Artifact-backed validation workflow

### ❌ Not Claimed
- Full tokenizer compatibility
- Transformer forward execution
- Logit generation
- Sampling correctness
- Generated token validity

---

## Why This Separation Matters

Prevents the common failure mode of treating **"model loaded"** as **"model runs."**

Phase 5 proves the runtime can touch real weights.  
Phase 6+ will prove the runtime reasons correctly.

---

## Next Validation Chain

### TG3-G1 — Tokenizer Parity
**Goal**: `reference tokenizer output == RawrXD tokenizer output`

**Evidence required**:
- Identical token IDs
- Identical byte pieces
- Identical handling of:
  - BOS/EOS
  - Whitespace prefixes
  - UTF-8 boundaries
  - Unknown tokens
  - Special tokens

**No inference needed yet.**

---

### TG3-G2 — First Logit Validation
**Goal**: `GGUF weights + runtime → logits`

**Evidence required**:
- Deterministic input prompt
- Deterministic position state
- Compare first output vector against reference

**Example**:
```
Prompt: "Hello"

Expected:
  logit[0] = ...
  logit[1] = ...
  ...
```

**Validation focus**:
- Embedding lookup
- RMSNorm
- QKV projection
- RoPE
- Attention
- FFN
- Output projection

---

### TG3-G3 — First Deterministic Token
**The actual milestone**:

```
prompt
  ↓
tokens
  ↓
forward pass
  ↓
logits
  ↓
argmax
  ↓
verified token ID
```

A successful TG3-G3 proves the entire minimal inference chain exists.

---

## Architectural Transition

The project has moved from:

```
Artifact Understanding ✅
  (Phase 5 complete)
```

to:

```
Behavioral Proof ⏳
  (TG3-G1: Tokenizer parity)
  (TG3-G2: First logits)
  (TG3-G3: First verified token)
```

---

## Important Constraint

**Resist adding new subsystems.**

Focus only on:
1. Closing the numerical correctness loop
2. Validating against reference (llama.cpp)
3. Passing TG3-G1, TG3-G2, TG3-G3

The remaining work is:
```
bytes → tensors → logits → token
```

Not more infrastructure. Only validation gates.

---

## Files Frozen

| File | Purpose | Status |
|------|---------|--------|
| `tg003_dequant_q4k.c` | Q4_K dequantization | ✅ Frozen |
| `tg003_quant_validation.c` | Validation metrics | ✅ Frozen |
| `tg003_real_tensor_validate.c` | Real tensor validation | ✅ Frozen |
| `tg003_transformer_block.c` | Transformer layer | ✅ Frozen |
| `tg003_tokenizer.c` | Tokenizer (partial) | 🟡 TG3-G1 target |
| `tg003_end_to_end.c` | Pipeline initialization | ✅ Frozen |

---

**Next Action**: Implement TG3-G1 (Tokenizer parity with llama.cpp)
