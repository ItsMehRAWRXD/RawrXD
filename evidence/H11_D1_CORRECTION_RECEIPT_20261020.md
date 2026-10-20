# H11 / D1 correction receipt — 2026-10-20

Branch: `local-30b-backend`
Model: `F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
Configuration: one worker, FP32 KV, Vulkan disabled for this numerical gate, causal prefill chunks 1/2/16/128.

## Source correction

- Loaded GGUF geometry is asserted before parity: 22 layers, hidden 2048, 32 query heads, 4 KV heads, head dimension 64.
- Batched GQA maps `query_head / group_size` to the bounded KV head.
- `prefillSerial` and `prefillBatched` publish post-final-norm hidden rows.
- Batched prefill embeds one causal chunk at a time.
- Correctness mode uses the production `AttentionWithCache` reducer after transactional chunk KV writes.

## Verification

| Prompt tokens | P1 chunk 1 | P2 chunk 2 | P3 chunk 16 | P4 chunk 128 | KV | max abs overall |
| ---: | :---: | :---: | :---: | :---: | :---: | ---: |
| 1 | PASS | PASS | PASS | PASS | byte exact | 0 |
| 2 | PASS | PASS | PASS | PASS | byte exact | 0 |
| 8 | PASS | PASS | PASS | PASS | byte exact | 0 |
| 30 | PASS | PASS | PASS | PASS | byte exact | 0 |
| 32 | PASS | PASS | PASS | PASS | byte exact | 0 |
| 128 | PASS | PASS | PASS | PASS | byte exact | 0 |

Evidence logs:

- `H11_GQA_HIDDENOUT_FIX_20261020.log`
- `H11_TWO_TOKEN_ATTENTION_REFERENCE_20261020.log`
- `H11_8TOKEN_ATTENTION_REFERENCE_20261020.log`
- `H11_FULL_PROMPT_ATTENTION_REFERENCE_20261020.log`
- `H11_32TOKEN_ATTENTION_REFERENCE_20261020.log`
- `H11_128TOKEN_ATTENTION_REFERENCE_20261020.log`

Build command:

```powershell
cmake --build build --target deep2_h11_prefill_parity --config Release --parallel 2
```

Build exit: `0`.

Executable SHA-256: `FB575E317D12ACED4FB6602ED8A06666E91E3935391A3113D3F4E48BC10B9A8E`.

This receipt certifies numerical correctness for the TinyLlama H11/D1 workload. It does not claim reduced GPU submissions, sustained throughput, speculative speedup, 150 TPS, multi-GPU execution, or release-gate completion.
