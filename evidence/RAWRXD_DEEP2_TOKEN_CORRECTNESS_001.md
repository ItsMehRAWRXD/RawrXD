# RAWRXD_DEEP2_TOKEN_CORRECTNESS_001

Date: 2026-10-23
Executable: `build_deep2_native/bin/Release/deep2_openai_server.exe`

## Source corrections

- GGUF template admission now preserves the model filename when
  `tokenizer.chat_template` is absent. TinyLlama is classified explicitly and
  uses its `<|role|> ... </s>` format.
- The HTTP adapter's serialized conversation is no longer formatted a second
  time by `Deep2Engine::generateStream`; this removes duplicated role headers
  from the prefill prompt.
- GPU forward arena reservation uses a bounded 4096-token working window by
  default, while the configured context limit remains available to KV
  admission. `DEEP2_GPU_ARENA_CONTEXT` can select a smaller explicit window.
- GPU quantized/prefetch admission failures now identify layer, tensor, type,
  shape, and failing stage.

## Live evidence

| Check | Result |
|---|---|
| MSVC Release server rebuild | PASS |
| `/health` and `/v1/chat/completions` | PASS |
| Llama prompt serialization | PASS; 17 tokens, one user turn and one assistant header |
| TinyLlama template classification | PASS; `ChatTemplate=tinyllama` |
| Llama CPU single-token generation | PASS; finite response (`Here`) |
| Llama GPU first-token dispatch | PASS; 476 forward calls, no CPU fallback on the one-token run |
| Llama GPU multi-token completion | FAIL; second-token path reports an FFN/GEMV boundary and falls back to host |
| Exact semantic response parity | NOT_CERTIFIED |
| Full-model certification | NOT_CERTIFIED |

Receipts and raw stderr logs:

- `deep2_llama_gpu_diag2.log.err` — one-token GPU forward (`GPU_FORWARD_CALLS=476`).
- `deep2_llama_gpu_budget4g.log.err` — multi-token failure at `ffn_gate_up`.
- `deep2_tinyllama_trace.log.err` — TinyLlama template and token IDs.

## Follow-up after `DEEP2_GPU_FFN_MULTITOKEN_001`

The first failing trace was identified as an admission-contract mismatch:
BIND16 required dual-device proof on a single-device run (`g1=0`). BIND16 and
BATCH2 are now gated on `vulkanDevices_.size() > 1`; single-device runs use the
ordinary packed GEMV path. The controlled two-token run then completed on GPU
with `FWD_G0=336` and `GPU_FORWARD_CALLS=364`, with no host fallback or BIND16
failure. An eight-token run also completed; control-token filtering was then
extended to Llama-3 markers (`<|eot_id|>`, `<|end_of_text|>`, and header tags).

This closes the diagnosed single-device multi-token dispatch blocker. Longer
8/32/128-token parity, independent oracle comparison, and throughput targets
remain pending and therefore certification remains `NOT_CERTIFIED`.
