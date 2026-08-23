# VAL-051.7 Baseline Fixture Set
# Frozen: 2026-08-22
# Source: VAL-051.6 15-token autoregressive validation

## Model Identity
- Model: G:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf
- Architecture: Codestral-22B
- Quantization: Q4_K_M
- Hidden: 6144, Layers: 56, Heads: 48, KV Heads: 8, HeadDim: 128
- Vocab: 32768

## Golden Token Sequence (15 tokens)
Position | TokenID | Notes
---------|---------|-------
0        | 9693    | First decode step
1        | 9693    | Repeat
2        | 10057   |
3        | 15285   |
4        | 10057   |
5        | 10057   |
6        | 3442    | Collapse begins
7        | 3442    |
8        | 3442    |
9        | 3442    |
10       | 3442    |
11       | 3442    |
12       | 3442    |
13       | 3442    |
14       | 3442    |

## Semantic Invariants
- All logits finite: YES
- All hidden states finite: YES
- Position monotonic: 2→14
- Invalid tokens: 0
- Non-finite logits: 0
- Hidden failures: 0
- Position failures: 0
- Exit code: 0

## Performance Baseline
- Decode latency: ~667–808 ms/token
- Layer latency: ~30–36 ms/layer
- Tokens/sec: ~1.25–1.50

## Structural Baseline
- Layers per forward: 56
- BatchedMatMul: 0 (T=1 decode)
- WeightLookup: ~2325 per forward
- AVX512Kernels: 0
- Repeated remap: 637 MB per layer

## Acceptance Criteria for VAL-051.7
1. Token sequence identical to golden (within FP tolerance)
2. All logits finite
3. All hidden states finite
4. Position monotonic
5. Remap count reduced or eliminated
6. Decode latency improved ≥2×
7. No regression vs VAL-051.6
