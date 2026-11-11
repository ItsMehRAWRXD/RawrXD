# Hyperconnection combine_norm lowering checkpoint

The second native Qwen4Exp lowering artifact is a Vulkan correctness kernel for the recovered `hc_combine_norm` contract.

- Source: `src/deep2/shaders/deep2_qwen4exp_hc_combine.comp`
- SPIR-V: `src/deep2/shaders/deep2_qwen4exp_hc_combine.spv`
- Inputs: residual `[tokens, hc_count*head_dim]`, block output `[tokens, head_dim]`, injection logits `[tokens, hc_count]`, norm weights.
- Outputs: combined residual and grouped RMS-normalized stream buffer.
- Recovered equation: `injection = 2*sigmoid(logits/hc_count)`; `out = residual + block*injection`; grouped RMS normalization with affine weight.
- SPIR-V compiler: `glslc` exit `0`.
- SPIR-V validator: `spirv-val` exit `0`.

This is a shader artifact checkpoint, not an executor binding. It uses F32 staging buffers so that descriptor/state semantics can be tested independently; the Q8 weight GEMM and bf16 rounding path remain separate certification work. Qwen4Exp remains `NOT_CERTIFIED`.
