# MoE full-logit parity: Strata residency ON vs OFF — 2026-11-21

Sprint gate: **does Strata expert residency change MoE inference numerics?**

## Setup

```
exe    F:\rawrxd\build\Release\deep2_strata_chat.exe
SHA256 AFE4C56B307A2CB45CBD6741E492647C8C2F308FF95D44F2C0C23A93DAE1F911
model  F:\rawrxd\models\deepseek-coder-v2_16b.gguf   (deepseek2 MoE, vocab 102400)
prompt "The capital of France is"   --max-new 6   GPU   argmax
two runs: --strata and --no-strata, each with --logits-out
```

Logits format per step: `[uint64 count][float32 * count]`, matching `ltt_tensor_invoke`.

## Strata ON

```
DISPATCH gpu_calls=7248 cpu_calls=0 fallback=<none> nonfinite_logits=0
S01_EXPERT_LEDGER observations=5616 hits=3528 misses=2088 evictions=0
                  hit_rate=0.6282 distinct_experts=696
CHAT_STATUS OK
```

## Strata OFF (control)

```
DISPATCH gpu_calls=7248 cpu_calls=0 fallback=<none> nonfinite_logits=0
S01_EXPERT_LEDGER observations=0 (tracking disabled)
CHAT_STATUS OK
```

## Full-logit comparison (102,400 logits per step, 6 steps)

```
step=0 cos=1.000000000 max_abs=0 argmax 317/317 match
step=1 cos=1.000000000 max_abs=0 argmax 317/317 match
step=2 cos=1.000000000 max_abs=0 argmax 317/317 match
step=3 cos=1.000000000 max_abs=0 argmax 317/317 match
step=4 cos=1.000000000 max_abs=0 argmax 317/317 match
step=5 cos=1.000000000 max_abs=0 argmax 317/317 match
WORST_COS 1.000000000   WORST_MAX_ABS 0   ARGMAX_MISMATCHES 0
```

**The logits are bit-identical with residency active.** 3,528 expert cache hits
produced exactly the same full-vocabulary distributions as re-uploading weights.

## Interpretation

* Strata residency is numerically transparent at the **full-logit** level on this
  MoE model — not merely at the token level (which was shown previously: 12/12
  identical tokens).
* Correctness of residency is now evidenced, not inferred.
* The previously reported DeepSeek-Coder-V2 incoherence is therefore a property of
  the base GGUF / greedy decoding, not a Strata residency defect.

## Caveats

* One prompt, 6 positions, single device, argmax decoding.
* No comparison against llama.cpp in this run; this is a Strata-on vs Strata-off
  differential, which is the right oracle for residency correctness but is **not**
  independent reference parity.
* `GPU Cmd Dispatches` (H11) still unwired; GPU attribution is `gpu_calls=7248`.

## Next

* Independent llama.cpp reference on the same teacher-forced tokens to move from
  "residency is transparent" to "Deep2 matches a third-party implementation".
* Dual-GPU per-device attribution.