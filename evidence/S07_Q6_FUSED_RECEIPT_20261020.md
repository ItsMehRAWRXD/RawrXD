# S07 Q4_K/Q6_K fused LM-head integration — 2026-10-20

The speculative verifier now reaches a build-independent fused Q4_K/Q6_K Vulkan GEMV path. TinyLlama's `output.weight` is Q6_K (`dims=[2048,32000]`), so the verifier passes the actual GGUF type and uses the correct vocabulary dimension (`dims[1]`). The shader supports up to eight token positions and reconstructs the same interleaved Q8_K activation values used by the serial quant-dot reference.

Build and shader checks:

- `glslc -O --target-env=vulkan1.2 src/deep2/shaders/deep2_qgemv_batch8row.comp -o src/deep2/shaders/deep2_qgemv_batch8row.spv`: exit 0.
- `cmake --build build --target deep2_spec_bench --config Release --parallel 2`: exit 0.
- executable SHA-256: `F70205D6DB85CA188C7424E5A54384EF85D92BE5DAF442A7C99EF81B5EC9174C`.
- fused shader SHA-256: `ABED7B0CA1FCA95BFB30F8D09A6A6DFCFA87F68F52E6CC7DF292EDADDD27C4C5`; source SHA-256: `8FF266D0868C54B431DD4A10D3EBC67D0855CD97D55D1D76268E5FB2A85B37BD`.
- runtime trace selected `F:/rawrxd/src/deep2/shaders\\deep2_qgemv_batch8row.spv` and reported zero CPU calls.

The differential witness (`RR_QK_FUSED_VALIDATE=1`, 4-token code run) reported Q6_K fused-vs-serial `max_abs=4.76837158e-06`, with identical greedy output and finite logits. Receipts: `evidence/S07_Q6_FUSED_VALIDATE_4_RUN5_20261020/`.

Controlled 128-token R9700 runs, TinyLlama Q4_K_M, gamma 4, repeat drafter, one benchmark process:

| workload | serial decode | fused speculative decode | serial TPS | speculative TPS | speedup | proposed/accepted | verify batches/positions | GPU calls | stream |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| code | 28279.9 ms | 29601.2 ms | 4.53 | 4.32 | 0.96x | 12 / 3 (25.0%) | 3 / 15 | 36098 / 37742 | 128/128 |
| prose | 28738.7 ms | 30070.4 ms | 4.45 | 4.26 | 0.96x | 8 / 0 (0.0%) | 2 / 10 | 47208 / 48614 | 128/128 |

Both arms had finite logits and zero CPU calls; the benchmark verdict was PASS. S07 acceleration remains OPEN because the fused projection does not yet reduce total target work or produce an end-to-end speedup. The scalar Q6 decode is deliberately correctness-first; vector Q6 tiling remains an optimization task after a matching witness.

Receipts: `evidence/S07_Q6_FUSED_128_BOTH_20261020/`, `evidence/S07_Q6_FUSED_16_BOTH_20261020/`, and `evidence/S07_Q6_FUSED_VALIDATE_4_RUN5_20261020/`.

## Rebuilt 128-token revalidation

The Release executable rebuilt after the Q6 integration produced the same correctness result on the isolated R9700 path. Executable SHA-256: `F70205D6DB85CA188C7424E5A54384EF85D92BE5DAF442A7C99EF81B5EC9174C`.

- Code: serial 4.54 TPS, fused speculative 4.33 TPS (0.95x); 12 proposed, 3 accepted; 36,098 vs 37,742 GPU calls.
- Prose: serial 4.50 TPS, fused speculative 4.27 TPS (0.95x); 8 proposed, 0 accepted; 47,208 vs 48,614 GPU calls.
- Both streams were 128/128 identical, finite, and CPU-call free. S07 remains OPEN.
- Fresh differential witness: `evidence/S07_Q6_FUSED_VALIDATE_4_RUN6_20261020/` (Q6 max_abs `4.76837158e-06`).
