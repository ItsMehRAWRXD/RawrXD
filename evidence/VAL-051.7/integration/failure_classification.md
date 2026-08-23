# VAL-051.7 — Gate 15: Failure Classification

## Document Identity
- **Gate:** 15
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Structured Error Taxonomy

Every failure carries:
- **Category** — classification
- **Error code** — specific identifier
- **Tensor** — involved tensor name
- **Layer** — layer index
- **Forward** — forward step
- **Position** — token position
- **Lease ID** — if applicable
- **Generation** — if applicable
- **Expected value** — what should have happened
- **Actual value** — what did happen
- **Source location** — file/line

---

## Categories

| Category | Prefix | Meaning |
|----------|--------|---------|
| B3 | `[B3_FAIL]` | Autoregressive state integrity gate |
| Residency | `[RESIDENCY_FAIL]` | Residency manager failure |
| Tensor | `[TENSOR_FAIL]` | Tensor metadata/loading failure |
| KV | `[KV_FAIL]` | KV cache failure |
| Attention | `[ATTENTION_FAIL]` | Attention computation failure |
| FFN | `[FFN_FAIL]` | FFN computation failure |
| Tokenizer | `[TOKENIZER_FAIL]` | Tokenization failure |
| Sampler | `[SAMPLER_FAIL]` | Sampling failure |
| Streamer | `[STREAMER_FAIL]` | Streamer state failure |
| Model | `[MODEL_FAIL]` | Model loading failure |
| Numerical | `[NUMERICAL_FAIL]` | NaN/Inf/nonfinite detection |
| Teardown | `[TEARDOWN_FAIL]` | Cleanup failure |

---

## Critical Rule

**Residency instrumentation must NOT overwrite or relabel B3 numerical failure.**

The `3.9e20` attention explosion is a **numerical defect**, not a residency defect.
It must be preserved independently with category `[NUMERICAL_FAIL]` or `[B3_FAIL]`.

---

## Example Outputs

```
[B3_FAIL] hidden state invalid pos=5 norm=0.000000000e+00
[RESIDENCY_FAIL] stale lease tensor=blk.0.wq lease=42 expected_gen=3 actual_gen=7
[TENSOR_FAIL] unknown tensor 'blk.99.wq' requested
[KV_FAIL] KV cache position mismatch: expected=5 actual=6
[ATTENTION_FAIL] attention output nonfinite: layer=0 head=3
[FFN_FAIL] FFN output zero: layer=0 after SwiGLU
[NUMERICAL_FAIL] logits contain NaN: pos=5 count=3
```
