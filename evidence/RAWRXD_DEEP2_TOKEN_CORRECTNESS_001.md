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

The remaining blocker is a real multi-token GPU state/FFN dispatch failure, not
service connectivity or prompt double-formatting. No certification claim is
made from the component or one-token result.
