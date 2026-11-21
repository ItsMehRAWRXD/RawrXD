# MoE boundary equivalence — structural finding — 2026-11-21

Sprint gate: **are Deep2's MoE ops comparable to llama.cpp at all?**

## Finding

The llama.cpp reference dump for `deepseek-coder-v2_16b.gguf` contains **no routed-expert
boundaries**. `ref/pos0` has, for MoE layers, only:

```
attn_norm_L1, q_L1, k_L1, v_L1, attn_preproj_L1, attn_resid_L1,
ffn_norm_L1, ffn_gate_L1, ffn_up_L1, ffn_swiglu_L1, ffn_down_L1,
resid2_L1, resid_in_L1
```

There is no `ffn_gate_inp` (router logits), no per-expert tensor, and no combined MoE
output. The dump tool only captures node names matching its rule table, so routed-expert
tensors are invisible in this reference.

Meanwhile Deep2's trace for the same block has explicit MoE ops:

```
op21 ffn_norm (2048)     op22 ffn_gate_inp.weight   op23 (pc=6)      op24 expert_choice (2048)
op25 ffn_gate_shexp (2816) op26 ffn_up_shexp (2816) op27 shared_up (2816)
op28 ffn_down_shexp        op29 shared_out (2048)
```

## Consequence for the 0.817 result

Deep2's `shared_out` (op29) was compared against llama.cpp's `ffn_down_L1`
(2048 elements) and scored cos 0.817. Since the reference dump exposes no routed-expert
tensors, `ffn_down_L1` is most plausibly the **shared expert's** down output — which makes
the comparison potentially valid for the shared path but **invalid for the routed sum**.

However, the shared expert's *inputs* match well:

| op | tensor | cos vs llama.cpp |
|---|---|---|
| 25 | `gate_shexp` | 0.999553 |
| 26 | `up_shexp` | 0.999666 |
| 27 | `shared_up` (swiglu) | 0.999548 |
| 29 | `shared_out` (after down) | **0.817447** |

So the shared expert's gate/up/swiglu match, but the tensor after the down projection does
not. That is a **specific, testable sub-hypothesis**: the shared-expert down projection
(or the aggregation that produces `shared_out`) diverges.

## Caveats

* Boundary equivalence is still not proven: llama.cpp may name the shared-expert down
  output differently, and `ffn_down_L1` could be a routed-expert accumulation.
* The routed-expert contribution is entirely absent from the reference, so the
  aggregation equation cannot be verified component-by-component with the current dump.

## Next (exact)

1. Extend `tools/llama_dump_intermediate.cpp` rules to capture MoE tensors: the router
  (`ffn_gate_inp`), per-expert gate/up/down, and the combined MoE output — then re-dump
  `pos0` and compare Deep2's ops 22–29 one-to-one.
4. In parallel, compare Deep2's `shared_out` against a **manually computed** shared-expert
  down projection from llama.cpp's `ffn_down_L1` + `ffn_swiglu_L1` to test the down-projection
  sub-hypothesis.
5. Only after that, decide between routing-semantics and kernel fixes.

## Status

```
REFERENCE_HAS_ROUTED_EXPERT_BOUNDARIES=NO
SHARED_EXPERT_UP_TO_SWIGLU=MATCH (0.9995+)
SHARED_EXPERT_POST_DOWN=0.817447 (suspect)
ROUTED_EXPERT_COMPARISON=BLOCKED (no reference tensors)
KERNEL_CHANGE=NOT_AUTHORIZED