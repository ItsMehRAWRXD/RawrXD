# Multi-Token Generation Agreement — KV-Cache Reuse

Model: llama3.2:3b (Q4_K). Seed token IDs: [1, 185]. Greedy, 8 decoded tokens
(9 positions of KV reuse). Same input IDs on both engines — no tokenizer in
the loop.

## Result

| Step | Token | Engine stream |
|------|-------|---------------|
| 1 | 26957 | Both, max_logit 9.297271 (Deep2) / 9.040588 (llama.cpp) |
| 2 | 320 | Both |
| 3 | 32482 | Both |
| 4 | 34190 | Both |
| 5 | 101453 | Both |
| 6 | 74541 | Both |
| 7 | 8 | Both |
| 8 | 104380 | Both |

**Generated token IDs: 8/8 identical.** Per-step max-logit relative
differences run 0.2%..3.0%, consistent with the Q8_K drift decomposition
(`q8_dot_decomposition.md`): the accumulated arithmetic-order drift does not
change the greedy argmax in this run.

## Reproducers

- llama.cpp reference: `llama_gen_ref <gguf> seed.txt 8` (prefill the seed as
  one batch, greedy decode with the model KV cache; F16 KV, no flash attention
  — the same settings as the node-dump reference).
- Deep2: `deep2_parity_trace.exe --model <gguf> --tokens "1 185" --generate 8`
  (production executor, CPU-pinned, persistent KV cache across positions).
- Both print `GENSTREAM: <id> <max_logit> ...` for direct comparison.

## Scope note

This certifies *token-identity* agreement under greedy decoding, not a
logit-level bound over unbounded length: drift accumulates with depth
(q8_dot_decomposition.md), so a longer horizon or a different prompt can hit a
decision-margin flip. The two robust gates are (a) this token-identity stream
on the agreed corpus, and (b) the per-layer tolerance table with the
decomposition explaining its mechanism.
