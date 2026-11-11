# Verdict

`GDN_PRODUCTION_REACHED=PASS_SCOPE`
`GPU_ONLY_EXECUTION=PASS_SCOPE`
`FINITE_LOGITS=PASS_SCOPE`
`FULL_MODEL_PARITY=OPEN`
`PROMOTE=0`
`CERTIFIED=0`

The current Qwen3.6 executor reaches the real Vulkan GDN path on the verified
35B GGUF, completes two tokens with `gpu_calls=2602`, `cpu_calls=0`, and emits
finite logits. The GDN component check does not fail.

Global/full-model certification remains open because the first token's GPU/CPU
diagnostic differs (`cos=0.9946897`, `max_abs=1.085`, argmax mismatch) and no
independent full-vocabulary oracle was provided. The CPU-pinned path is a
diagnostic comparison, not an absolute oracle; the evidence identifies a real
first-divergence boundary but not its root cause.

