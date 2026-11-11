# DeepSeek R1 32B native smoke — 2026-10-20

Model: `F:/rawrxd/models/deepseek-r1_32b.gguf` (SHA-256 `6150cb382311b69f09cc0f9a1b69fc029cbd742b66bb8ec531aa5ecf5c613e93`).

The universal GGUF reader identified the file as `qwen2` / DeepSeek R1 Distill Qwen 32B with 64 layers, hidden size 5120, 40 attention heads, vocabulary 152064, and context 131072. Vulkan initialized on the AMD Radeon AI PRO R9700 and selected the row-8 Q6 shader.

The first launcher observation ended before its receipt was visible, so it was retained as a diagnostic trace. A redirected retry completed cleanly with exit code `0` and produced `evidence/DEEPSEEK32B_ROW8_8TOK_R2_20261020/SPEC_BENCH_RECEIPT.txt`:

- 8-token native GPU serial decode: 2509.1 ms (`3.19 TPS`), `gpu_calls=32712`, `cpu_calls=0`.
- Speculative decode: 5680.4 ms (`1.41 TPS`), 0/8 drafts accepted, exact stream agreement, finite logits.
- Architecture and Vulkan initialization passed; forward correctness passed for this smoke workload.

DeepSeek 32B is therefore **loadable and forward-correctness PASS for the 8-token smoke**, but its sustained performance and speculative acceleration remain open. The 1.41 TPS speculative result is a negative performance result, not a certification target. The earlier diagnostic stdout/stderr captures remain in `evidence/DEEPSEEK32B_ROW8_8TOK_R2_20261020/` and `...R3...`.
