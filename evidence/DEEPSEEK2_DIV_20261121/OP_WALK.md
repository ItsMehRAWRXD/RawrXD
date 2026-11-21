# DeepSeek2 op walk vs llama.cpp — first divergent activation — 2026-11-21

Sprint gate: **name the first materially divergent tensor vs llama.cpp**

## Method

Position 0, `deepseek-coder-v2_16b.gguf`, tokens `100000 549`.
For every Deep2 op payload of identical element count, the best-matching llama.cpp
boundary (canonical names, duplicates excluded) was selected and cosine / max_abs
recorded. **Weight tensors (`pc=2` entries such as `blk.N.attn_output.weight`) are
not activations** and their matches are meaningless — they are marked and excluded.

## Block 0 (dense FFN) — every activation matches

| op | activation | elements | best reference | cos | max_abs |
|---|---|---|---|---|---|
| 7 | `attn_proj` | 2048 | attn_resid_L0 | 0.999935 | 0.0055 |
| 8 | `ffn_norm` | 2048 | ffn_norm_L0 | 0.999891 | 0.0195 |
| 9 | `gate` | 10944 | ffn_gate_L0 | 0.999781 | 0.0199 |
| 10 | `up` | 10944 | ffn_up_L0 | 0.999699 | 0.0122 |
| 11 | `swiglu` | 10944 | ffn_swiglu_L0 | **0.999987** | 0.0173 |
| 12 | `ffn_down` | 2048 | ffn_down_L0 | 0.999893 | 0.0183 |
| 13 | `ffn_out` | 2048 | resid2_L0 | 0.999916 | 0.0179 |

Plus the previously measured `attn_norm_L0` (1.000000000), `q_L0` (0.999977),
`k_L0` (0.999998), `v_L0` (0.999950).

**The dense block is numerically correct against llama.cpp.**

## Block 1 (first MoE block)

| op | activation | elements | best reference | cos | note |
|---|---|---|---|---|---|
| 15 | `attn_norm` | 2048 | attn_norm_L1 | 0.999974 | ok |
| 16 | `q` | 3072 | q_L1 | 0.999116 | degraded |
| 17 | `k` | 3072 | k_L1 | 0.999984 | ok |
| 18 | `kv` | 2048 | attn_preproj_L1 | 0.998450 | degraded |
| 20 | `attn_resid` | 2048 | attn_resid_L1 | 0.999916 | ok |
| 21 | `ffn_norm` | 2048 | ffn_norm_L1 | 0.999749 | ok |
| 25 | `gate_shexp` | 2816 | ffn_gate_L1 | 0.999553 | ok |
| 26 | `up_shexp` | 2816 | ffn_up_L1 | 0.999666 | ok |
| 27 | `shared_up` | 2816 | ffn_swiglu_L1 | 0.999548 | ok |
| **29** | **`shared_out`** | 2048 | ffn_down_L1 | **0.817447** | **first material mismatch** |

## Finding

* Every dense-block activation matches llama.cpp at cos ≥ 0.9997.
* In the first MoE block the **shared-expert projections** (gate/up/swiglu) still match
  at ≥ 0.9995, but the **MoE output aggregation** (`shared_out`, op29) matches at only
  **0.817** with max_abs 1.56.
* Deep2's own GPU-vs-CPU trace also first diverges at `block 1 moe_out`, so both
  findings point at the same place: the **MoE output/aggregation stage**.
* The final-logit mismatch (cos 0.778) is consistent with an error introduced at the
  first MoE block and compounding through 26 more blocks.

## Caveats

* For MoE blocks, llama.cpp's `ffn_down_L1` is not guaranteed to be the same tensor
  as Deep2's `shared_out` (shared-expert down output). The 0.817 is a strong signal,
  not a proven one-to-one comparison; the expert-combine tensors must be compared
  explicitly (router logits, selected experts, weights, weighted sum).
* Weight-tensor ops (pc=2) were excluded as non-activations.
* Single position, single model, CPU trace payloads (`cpu_pos0_op*.f32`).

## Next

1. Compare the MoE router outputs (`ffn_gate_inp` = expert_choice) and the expert
  weighting/aggregation tensors explicitly, not by best-match.
2. Confirm which llama.cpp boundary corresponds to Deep2's `shared_out` and the
  combined MoE output.
3. Only then decide between a routing-semantics fix and an expert-output kernel fix.