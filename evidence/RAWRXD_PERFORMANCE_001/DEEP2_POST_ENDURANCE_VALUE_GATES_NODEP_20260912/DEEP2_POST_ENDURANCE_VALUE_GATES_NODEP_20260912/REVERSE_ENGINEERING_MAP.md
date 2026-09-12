# Reverse-engineering map: what remains to close the $100–140M and 70B proof gates

## A. Llama 3.2 Q2_K quality

Instrument **after final logits and after token selection**. The diagnostic split is mechanical:

| Observation | Primary suspect |
|---|---|
| tokenizer round-trip fails | tokenizer / special-token vocabulary |
| template predicate fails | Llama-3.2 chat template / BOS/EOS construction |
| logits NaN/Inf | quant decode / matmul / normalization / logits path |
| selected token repeats but argmax changes | sampler / penalty / RNG transform |
| argmax itself repeats pathologically | upstream logits, Q2_K decode, LM head, prompt state |
| trace sane but text-level n-gram collapse | detokenization or insufficient trace depth |

Do not repair continuity, residency, or BIND16 to fix quality; those lanes are sealed.

## B. Clean model matrix

Required minimum rows: Llama 3.2 Q2_K, TinyLlama, one coder family, one 30–40B family, and one 70B+ family when available. A row is PASS only if positional CLI exits zero, generated tokens are nonzero, mock backend is zero, and the quality analyzer passes.

## C. 70B+ constrained-memory proof

The proof needs three separate facts, all preserved raw:

1. **Identity:** exact GGUF SHA-256, quant, parameter count, prompt-corpus SHA-256, source commit/build identity.
2. **Memory:** peak host working set/private bytes plus engine-emitted device-resident bytes. If device telemetry is missing, record UNAVAILABLE and do not mint the constrained-memory claim.
3. **Throughput:** fixed generated-token count, warmup excluded, >=3 measured trials, wall-time TPS median, zero retries. Compare against an external engine with the same GGUF when supported.

The source drop deliberately does not vendor competitor code. External binaries are process-invoked only, preserving the no-dependency rule.
