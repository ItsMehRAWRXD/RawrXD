# Qwen4Exp PLE lowering checkpoint

The first native lowering artifact is a Vulkan compute shader for the PLE causal depthwise short convolution.

- Source: `src/deep2/shaders/deep2_qwen4exp_ple.comp`
- SPIR-V: `src/deep2/shaders/deep2_qwen4exp_ple.spv`
- Contract: `X[tokens, channels]`, depthwise `W[kernel, channels]`, causal state `[kernel-1, channels]`, output `Y[tokens, channels]`, carried state output.
- Canonical geometry: kernel `4`, channels `10240`.
- Compile: `glslc` exit `0`.

The shader is an artifact checkpoint only. It is not bound into `Executor::Bind`, because descriptor allocation, state lifetime, and independent reference parity have not yet been validated. Qwen4Exp remains `NOT_CERTIFIED` and the executor remains fail-closed.
