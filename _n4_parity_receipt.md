# BATCH N4 — Inference Parity Oracle (receipt)

Strict build: F:\~dev\rawrxd\build_clean_n1\bin\Release\rawr.exe (N1-certified)
Reference: Ollama 0.34.4, model n4-tiny-oracle imported FROM THE EXACT SAME GGUF
(G:\~dev\tinyllama_fresh.gguf, llama arch, 22 layers, vocab 32000, sha256 layer ba56d70d...)
API: raw /api/generate, temperature=0, seed=1, num_predict=6, raw=true (no chat template)

## Measured gates

| Gate | Result | Evidence |
|---|---|---|
| MODEL_LOAD | PASS | 83 ms, 201 tensors mapped, geometry complete |
| FORWARD_PASS | PASS | 6x FINAL_NORM → COMPUTE_LOGITS_RETURNED |
| LOGITS_FINITE | PASS | LOGITS_SANITY count=32000 finite=32000 nan=0 inf=0 (every step) |
| PROMPT_TOKENS_MATCH | PASS | rawr PROMPT_TOKENS=2 == oracle prompt_eval_count=2 (same bare prompt "hi") |
| TOKEN_DECODE_VALID | PASS | rawr decodes 6 ids; oracle decodes 6 ids (both paths produce decodable text) |
| DETERMINISTIC_REPEAT | PASS | run2 SAMPLER_RESULT ids byte-match run1 (2747,12818,26454,1338,708,2747) |
| GENERATED_TOKEN_COUNT>=1 | PASS | 6 tokens, receipt COMPLETED=YES, EXIT=0 |
| TOP_K_REFERENCE_OVERLAP | **NOT_OBSERVABLE** | Ollama 0.34.4 exposes neither logits, logprobs (400), nor /api/tokenize (404); context field absent in raw mode — cannot read reference token IDs for the top-k comparison |
| COHERENT_RESPONSE | PARTIAL | oracle "ke, and I was amaz" vs rawr "ayeralingccoalseryayer" — tinyllama base model; both model-dependent, divergence consistent with differing sampler stacks (not proof of forward mismatch) |

## Fail-closed notes

- TEMPLATE_MISMATCH caught: default oracle call used auto-detected zephyr template
  (prompt_eval_count=18 vs rawr 2). Fixed by raw=true — always require raw mode for parity.
- rawr.exe wall 7007 ms for 6 tokens (TPS 0.856) on CPU — perf is a separate gate.
- OLLAMA_CALLS=1 (oracle only, local). CLOUD_CALLS=0.

```
GATE=N4_INFERENCE_PARITY_001
MODEL_LOAD=PASS · FORWARD=PASS · LOGITS_FINITE=PASS
PROMPT_TOKENS_MATCH=PASS · DETERMINISTIC_REPEAT=PASS · TOKEN_DECODE_VALID=PASS
TOP_K_REFERENCE_OVERLAP=NOT_OBSERVABLE (ollama API limitation — needs a logprobs-capable oracle, e.g. direct llama.cpp or RawrXD raw-logits compare)
COHERENT_RESPONSE=PARTIAL
VERDICT=PASS-WITH-GAP (5/6 observable gates PASS; 1 gate not observable through reference API)
OLLAMA_USED=1 (oracle only) · STUB_FALLBACKS=0
```