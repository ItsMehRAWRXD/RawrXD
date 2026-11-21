# MoE Strata vs non-Strata greedy parity — 2026-11-21

Sprint gate: **does expert residency preserve correct MoE inference?**

## Setup

```
exe   F:\rawrxd\build\Release\deep2_strata_chat.exe
model F:\rawrxd\models\deepseek-coder-v2_16b.gguf   (deepseek2, MoE)
prompt "The capital of France is"   --max-new 12   GPU   argmax (deterministic)
two runs: --strata  and  --no-strata
```

## Strata ON

```
bound ops=458 (23060.4 ms)
prefill_done 7166.5 ms
DISPATCH gpu_calls=10268 cpu_calls=0 fallback=<none> nonfinite_logits=0
S01_EXPERT_LEDGER observations=7956 hits=5724 misses=2232 evictions=0
                  hit_rate=0.7195 distinct_experts=744
CHAT_STATUS OK
```

## Strata OFF (control)

```
bound ops=458 (21703.7 ms)
prefill_done 10357.7 ms
DISPATCH gpu_calls=10268 cpu_calls=0 fallback=<none> nonfinite_logits=0
S01_EXPERT_LEDGER observations=0 hits=0 misses=0 evictions=0 hit_rate=0.0000
CHAT_STATUS OK
```

## Comparison

```
TOKENS_IDENTICAL (12/12)
```

The generated token IDs are identical across both runs, so expert residency is
numerically transparent on this MoE workload: 5,724 cache hits and 2,232 misses
produced exactly the same greedy continuation as running without residency.

## Consequences

* The previously reported DeepSeek-Coder-V2 incoherence is a property of the base
  GGUF's greedy output, **not** a Strata residency defect — the same tokens are
  produced with and without residency.
* Strata residency is now evidenced through the chat path (not only the benchmark)
  on a real MoE model: 71.95% expert hit rate, 0 evictions.
* Prefill was faster with residency (7,166 ms vs 10,357 ms) on this run, though a
  single sample is not a performance claim.

## Caveats

* 12 tokens, one prompt, greedy decoding, one device.
* No full-vocabulary logit comparison was captured for this pair (the harness prints
  token IDs, not logits); strict logit parity remains OPEN.
* `GPU Cmd Dispatches` (H11) remains unwired; GPU attribution is `gpu_calls=10268`.

## Next

* Dual-GPU per-device attribution (R9700 + RX 7800 XT).
* Full-logit capture from the chat harness to close strict parity on a MoE model.