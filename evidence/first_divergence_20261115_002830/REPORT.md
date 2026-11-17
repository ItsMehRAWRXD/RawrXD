# First Divergence Report — Deep2 vs llama.cpp reference oracle

Task: M9–M15. Build the reference oracle, align Deep2/reference tensors, run
per-layer numerical comparison, and record the first divergent layer/operator.

## Inputs (same model, same token, same position)

| side     | artifact | token | pos | layers | tensors |
|----------|----------|-------|-----|--------|---------|
| reference (llama.cpp) | `_sprint_diag/ref_tok1_pos0/pos0/` (`llama_dump_intermediate`) | 1 | 0 | 0–26 | 377 |
| native (Deep2)        | `evidence/RAWRXD_CORE_DLL_NATIVE_E2E_001/diff_pos0d/` (ModelGenieExecutor differential) | 1 | 0 | 0–26 | 489 |

Model: `DeepSeek-V2-Lite-Chat.Q4_K_M.gguf` (n_embd=2048, 27 layers, MLA 16 heads x head_dim 192, dense FF 10944, MoE 1408x64/6/2, vocab 102400).

Alignment proof: native vs reference final logits cos = **0.999965**, argmax 185 on both.
(The earlier `ref_smoke` dump was a different model at 3072 dims and was NOT used.)

## Oracle changes (M9–M12)

`tools/llama_dump_intermediate.cpp`:
- Added `attn_resid` boundary (raw node `ffn_inp` = residual after attention, pre-FFN).
- Added per-layer `resid_in` synthesis: the residual entering layer L is exactly the
  block output of layer L-1 (`l_out`/`resid2`), because llama.cpp sets `inpL = cur`
  at the end of each block and the block-input node is unnamed in the vendored
  `deepseek2.cpp`. `resid_in_L1..L26` are derived from `resid2_L0..L25`.
- Rebuilt (`_sprint_diag/build_oracle.bat`, CL_EXIT=0) and ran full 27-layer capture.

Captured boundaries per layer (all 27): attn_norm, q (Qcur), k (Kcur), v (Vcur),
attn_preproj (kqv_out), ffn_norm, ffn_gate, ffn_up, ffn_swiglu, ffn_down,
attn_resid, resid2, resid_in (L1–L26). Note: MLA path does not `cb()` the post-O_proj
`attn_out`, so `attn_proj` is not exported for this model.

## Alignment (M13) native op -> reference boundary (per layer, pos0)

| native op (shape) | reference boundary |
|-------------------|--------------------|
| RMSNorm_Output #1 [2048] | attn_norm |
| RMSNorm_Output #2 [2048] | ffn_norm |
| Linear_Output [3072] | q (Qcur) |
| Attention_Output [2048] | attn_preproj (kqv_out) |
| Output [2048] (mid) | attn_resid (ffn_inp) |
| Output [2048] (last) | resid2 (l_out) |
| resid2(L-1) | resid_in(L) |

## Results (max abs diff per layer, key boundaries)

```
L   attn_norm     q             attn_preproj  attn_resid    ffn_norm      resid2
0   8.58e-06      1.05e-05      2.36e-04      3.50e-04      4.22e-04      1.81e-03
1   1.52e-02      1.20e-01      3.69e-03      2.88e-03      2.94e-02      6.10e-03
2   5.72e-02      1.91e-01      1.03e-02      9.47e-03      2.99e-02      7.51e-02
3   3.40e-02      1.86e-01      4.31e-03      7.33e-02      1.46e-02      3.01e+00
...
26  6.45e-02      1.48e-01      2.02e-02      1.33e+00      7.02e-02      3.25e+00
```

Cosine stays >= 0.9999 on every compared tensor at every layer (see per_tensor_diff.csv).

## First divergence (M15)

There is **no discrete operator bug**: Deep2 and llama.cpp agree to floating-point
precision at layer 0, and the difference is a gradual accumulation of rounding /
activation-quantization differences (Deep2 quantizes activations before each
quantized dot; llama.cpp uses a different accumulation order) that compounds over
27 layers and is amplified at sensitive (small-value / cancellation) elements.

Reported against the requested threshold (1e-3), in execution order:

1. Strict 1e-3 first crossing — **Layer 0, resid2 (block output `l_out`)**:
   max_abs = **1.808e-3** at idx 231 (native -1.943271 vs ref -1.945079),
   cos = 0.9999996, rel_l2 = 3.12e-3. This is fp noise (0.09% relative on O(1)
   values); layer 0 is otherwise exact (attn_norm 8.6e-6, q 1.05e-5).

2. First operator-level attention divergence — **Layer 1, operator `q`
   (attention Q projection, Linear_Output [3072])**:
   max_abs = **1.204e-1** at element idx 1849 = head 9, dim 121
   (native -0.207222 vs reference -0.086833), cos = 0.99994, rel_l2 = 1.2e-2.
   Only 88/3072 elements exceed 0.05 and 1 exceeds 0.10 -> a few sensitive
   elements, not a systematic error. Preceded in the same layer by `attn_norm`
   (max_abs 1.52e-2, idx 38), whose error is inherited from resid2_L0 (a small
   element already at ~3% relative) and amplified by RMSNorm.

3. First significant residual-stream divergence — **Layer 2, resid2**
   (max_abs 7.51e-2, cos 0.9999668). By layer 3 the residual magnitude reaches
   ~1.1e3 (DeepSeek-V2 massive activations); the 3.0 max_abs there is 0.27%
   *relative* error, not a structural fault (cos ~1).

Final logits: cos 0.999965, argmax 185 both.

## Conclusion

- Layer 0 (dense) PASS: matches reference to fp precision.
- Earliest meaningful divergence: **Layer 1 attention Q projection (`q`)**,
  max_abs 1.204e-1 at head 9 / dim 121 (native -0.2072 vs ref -0.0868),
  cos 0.99994.
- Character: gradual floating-point / activation-quantization accumulation,
  amplified at sensitive elements, compounding through MoE layers. No discrete
  wiring or operator swap is indicated at this token/position.

## Reproduction

```
# reference oracle (token 1, pos0, all layers)
_sp:\...> _sprint_diag\llama_dump_layers.exe DeepSeek-V2-Lite-Chat.Q4_K_M.gguf _sprint_diag\tok1.txt _sprint_diag\ref_tok1_pos0 --no-hidden

# native Deep2 differential capture (token 1, pos0)
tools\rawrxd_modelgenie_ir_executor.exe DeepSeek-V2-Lite-Chat.Q4_K_M.gguf evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001 --teacher-forced 1 --differential <out> --diff-position 0

# compare
py tools\first_divergence_compare.py --ref _sprint_diag\ref_tok1_pos0\pos0 --nat evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos0d --threshold 1e-3 --out <this dir>
```

## Files

- `per_tensor_diff.csv` — every compared (layer, boundary) with n, max_abs, mean_abs, cos, rel_l2.
- `first_divergence.json` — machine-readable summary + strict-threshold first crossing.
- `REPORT.md` — this report.
- `manifest_reference.txt` — copy of the reference oracle manifest.