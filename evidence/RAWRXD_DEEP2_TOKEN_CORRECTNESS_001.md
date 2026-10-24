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

## Sustained single-GPU ladder

Using the same Llama 3.2 Q2_K model with temperature `0` and top-p `1`:

| Request | Committed | Wall time | Observed TPS | GPU calls | Host fallback |
|---:|---:|---:|---:|---:|---|
| 8 | 3 (EOS) | 4.6 s | 0.47 | 392 | none |
| 32 | 32 | 15.8 s | 3.07 | 1,456 | none |
| 128 | 128 | 49.8 s | 2.87 | 4,144 | none |

The 32- and 128-token requests completed with finite text, nonzero GPU
forward calls, and no observed fallback markers. These are execution and
stability passes only; the throughput target and independent CPU/oracle parity
remain open. Dual-device execution was not exercised in this receipt.

## CPU/GPU deterministic control

Same GGUF, prompt, temperature `0`, top-p `1`, and `max_tokens=32`:

- GPU: 32 committed tokens, 15.48 s, coherent finite text.
- CPU control: 1 committed token (`I`), 19.44 s, then EOS.

This is an explicit parity failure. It confirms that sustained GPU execution
does not yet establish numerical equivalence with the host reference. The
next investigation must compare first-token logits and token IDs at the first
divergence; certification remains `NOT_CERTIFIED`.

## First-token numerical comparison (`DEEP2_FIRST_TOKEN_PARITY_020`)

With `RAWRXD_STAGE_DIGEST=1` and `RAWRXD_LOGIT_TOP10=1`, identical `Say hello`
and deterministic settings produced the same first-token argmax. The captured
position-20 tensors were compared from the binary stage dumps:

| Tensor | Max absolute difference | RMS difference | Argmax |
|---|---:|---:|---|
| Final hidden (3072) | `6.9886e-06` | `2.1329e-06` | n/a |
| Output logits (128256) | `1.0575e-01` | `2.1598e-02` | GPU/CPU both `4936` |

Top-10 token IDs were identical at the first position (ordering of close
non-argmax values varied slightly). All values were finite. This localizes the
first-token difference to the output projection/logit stage rather than the
hidden-state forward path. It is not yet a numerical parity pass: the logits
need a defined tolerance and multi-token KV-state comparison before promotion.
