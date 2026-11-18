# Qwen3.5 first-divergence localization

Source baseline: `a4e68938b0`
Model: `pdurugyan_qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2_latest.gguf`
Input: token `1`, position `0`

The real GPU run completed with 273 GPU calls and zero CPU fallbacks. Logits
were finite (`248320/248320`), with GPU/CPU argmax `760/760`, cosine
`0.9984229`, and maximum absolute error `1.072`.

Boundary comparison results:

- Blocks 0-2 residuals: maximum absolute error at or below `1.91e-6`.
- Block 3 attention context before output projection: maximum absolute error
  `8.34e-7`, RMS `4.04e-8`.
- Block 3 `attn_output.weight` projection: maximum absolute error `4.167438`,
  RMS `0.1081151`, worst index `3994`.
- The block-3 output projection is GGML type `12` (`Q4_K`) with dimensions
  `[4096,4096]` and input width `4096`.

Conclusion: the first major numerical divergence is the block-3 Q4_K output
projection. Attention geometry, RoPE, score computation, softmax, and context
formation are not the first failing boundary in this fixture. No tolerance was
changed and no fallback was used to obtain these measurements.

Certification remains held pending a Q4_K projection repair and independent
reference parity.
