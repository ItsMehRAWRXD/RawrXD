# DeepSeek R1 32B native smoke blocker — 2026-10-20

Model: `F:/rawrxd/models/deepseek-r1_32b.gguf` (SHA-256 `6150cb382311b69f09cc0f9a1b69fc029cbd742b66bb8ec531aa5ecf5c613e93`).

The universal GGUF reader successfully identified the file as `qwen2` / DeepSeek R1 Distill Qwen 32B with 64 layers, hidden size 5120, 40 attention heads, vocabulary 152064, and context 131072. Vulkan initialized on the AMD Radeon AI PRO R9700 and selected the row-8 Q6 shader.

The native process terminated after pipeline initialization and before producing a benchmark receipt or finite-logit result. Repeated 8-token and 1-token attempts both stopped at the same boundary. Captured stdout is preserved in `evidence/DEEPSEEK32B_ROW8_8TOK_R2_20261020/stdout.txt` and `evidence/DEEPSEEK32B_ROW8_8TOK_R3_20261020/stdout.txt`; stderr was empty. Because no clean process exit or forward result was recorded, this model is **NOT CERTIFIED** for native forward execution.

This is a genuine model-specific execution blocker, not a performance result. The next repair should instrument the first Qwen2 graph operation and add a fail-closed exception/SEH receipt around model execution before attempting 120B or 671B models.
