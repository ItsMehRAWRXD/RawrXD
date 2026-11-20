# Headless Strata chat — Phase 1B acceptance (2026-11-20)

Sprint gate: **real, GPU-executed, streamed, cancellable Strata chat**

## Setup

```
exe    F:\rawrxd\build\Release\deep2_strata_chat.exe
SHA256 7AE2B9F025AE8239B4476CF97C8623E1EC5668C2C70825C7A110B84EA9960E9E
model  tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf  (dense — no MoE experts)
config GPU, Strata tracking, LRU policy 0
```

## Run 1 — streaming smoke

```
deep2_strata_chat.exe --model <gguf> --prompt "The capital of France is" --max-new 16 --gpu --strata
```

```
bound ops=311 (2948.2 ms)
prefill_done 3341.3 ms
[tok 0..15] ' a' ' city' ' that' ' has' ' been' ' sh' 'aped' ' by' ' its' ' history' ','
            ' culture' ',' ' and' ' trad' 'itions'
DISPATCH gpu_calls=3255 cpu_calls=0 fallback=<none> nonfinite_logits=0
CHAT_STATUS OK
```

Generated text: **“a city that has been shaped by its history, culture, and traditions”**
— coherent continuation, emitted one token at a time as produced.

## Run 2 — cancellation and recovery

```
--max-new 32 --cancel-after 5
[tok 0..4] ... CANCELLED after 5 tokens
DISPATCH gpu_calls=1550 cpu_calls=0 fallback=<none> nonfinite_logits=0
CHAT_STATUS CANCELLED   exit 0

# second request in a fresh process, same model
--prompt "One plus one is" --max-new 8
DISPATCH gpu_calls=1860 cpu_calls=0 fallback=<none> nonfinite_logits=0
CHAT_STATUS OK          exit 0
```

## Acceptance matrix

| Test | Result |
|---|---|
| Clean build | PASS |
| Real model load | PASS |
| Prompt tokenization | PASS (`CanonicalTokenizer`) |
| GPU prefill | PASS (3,341 ms) |
| GPU decode | PASS (16 tokens) |
| Incremental streaming | PASS (per-token lines) |
| Cancellation | PASS (`CANCELLED after 5`, exit 0) |
| Post-cancellation request | PASS (`CHAT_STATUS OK`) |
| Finite logits | PASS (0) |
| CPU fallback | **0** |
| Clean shutdown | PASS (exit 0) |

## Caveats

* `S01_EXPERT_LEDGER observations=0` — expected: TinyLlama is dense, so there are no
  MoE experts to track. Strata residency must be re-measured on an MoE model
  (deepseek-coder-v2_16b) to claim residency in the chat path.
* GPU attribution comes from `ex.Stats().gpu_calls` (3,255) and `cpu_calls=0`; the
  Vulkan device was initialised and the same executor the benchmark uses ran the
  forward. `GPU Cmd Dispatches` (H11) is still not wired.
* Single prompt shape, single device.

## Next

* Run the same harness on `deepseek-coder-v2_16b.gguf` to show expert-ledger hits
  through the chat path, not just the benchmark.
* Dual-GPU per-device attribution (`--device 0/1` + `deep2_dualgpu_forward`).