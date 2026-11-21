# DeepSeek2 first-divergent tensor (position 0) — 2026-11-21

Sprint gate: **locate the first divergent tensor vs llama.cpp**

## Inputs

```
model   deepseek-coder-v2_16b.gguf
tokens  100000 549 6077 280 7239 317
Deep2   deep2_gpu_certify.exe --tokens "100000 549" --dump op_trace_run
ref     evidence/LLAMA_REF_MOE_20261121/ref/pos0  (403 boundaries)
```

## Deep2's own GPU-vs-CPU trace divergence (internal diagnostic)

```
FIRST_TRACE_DIVERGENCE pos=0 index=24 block=1 op=moe_out weight=expert_choice
  cos=0.999795589 max_abs=0.004002 rms=0.001205
CERT_STATUS=EXECUTION_PASS_WITH_INTERNAL_DIAGNOSTIC
```

Deep2's GPU and CPU paths agree closely with each other (cos ≥ 0.9998), so the
GPU-vs-CPU kernel difference is **not** the source of the large mismatch against
llama.cpp.

## First ops vs llama.cpp (position 0, best-matching boundary variant)

| op | tensor | elements | cos vs llama.cpp | max_abs |
|---|---|---|---|
| 2 | `attn_norm_L0` | 2048 | **1.000000000** | 4.8e-7 |
| 3 | `q_L0` | 3072 | 0.999976659 | 0.0809 |
| 4 | `k_L0` | 3072 | 0.999997959 | 0.0132 |
| 5 | `v_L0` (dup1) | 2048 | 0.999950314 | 0.0041 |

So the embedding, pre-attention normalization and the Q/K/V projections all match
llama.cpp to ≥ 0.99995 cosine with small absolute error.

## Conclusion

The first divergence is **not** in embedding, normalization, or the QKV projections.
Deep2's own first GPU-vs-CPU divergence is at `block 1, moe_out (expert_choice)`,
which is consistent with the large final-logit mismatch (cos 0.78) originating in
the **MoE path** (expert selection / expert output combination) rather than in
attention projections.

## Caveats

* Only the first six ops of block 0 were compared; the first *divergent* op is
  still to be identified by walking forward until cosine drops materially.
* DeepSeek2 MLA has a compressed KV representation; the compared tensors match
  llama.cpp element counts, which supports the mapping but does not prove the
  attention core (scores/softmax/output) is correct.
* GPU attribution for this run: Deep2 internal counters only.

## Next

1. Continue the walk from op 6 through the block-1 attention and into `moe_out`,
  recording cos/max_abs per op, and stop at the first op below a stated tolerance.
2. Compare the MoE expert-choice weights and expert outputs separately.
3. Do not modify kernels until that op is named.