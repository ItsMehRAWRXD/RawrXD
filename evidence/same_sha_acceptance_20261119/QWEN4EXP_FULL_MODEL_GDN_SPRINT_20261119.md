# Qwen4Exp full-model GDN sprint

## Result

The existing real Vulkan GDN operator probe passes, but this checkout does not contain a production Qwen4Exp full-model runner that can be executed for certification.

## Evidence

- Source SHA: `e3e0531ed7d361799c746e71b9c0ffd2b34e7dc4`
- Candidate local model: `F:\rawrxd\models\bigdaddygnative_latest.gguf`
- Candidate model size: `25,463,410,912` bytes
- Available Qwen4Exp executable: `deep2_qwen4exp_gdn_probe.exe` only
- Existing probe result: one real Vulkan GDN dispatch, output/state parity PASS, exit `0`
- Full-model certifier executable: not present in `build/bin/Release`

## Source-level blocker

`src/deep2/runtime_graph_executor.cpp` fail-closes unsupported graph operators during binding. The Qwen4Exp full-model path is not wired to the verified GDN descriptor/state lifecycle and no executable in the current build can run the candidate model through a multi-token production graph.

The repository's CMake comments explicitly classify `deep2_qwen4exp_gdn_probe` as an operator-only certificate and state that it does not advance the full-model gate.

## Disposition

```ini
GDN_OPERATOR_VULKAN=PASS
QWEN4EXP_FULL_MODEL_RUN=NOT_RUN
MULTI_TOKEN_GDN_STATE=NOT_VERIFIED
FULL_MODEL_GPU_DISPATCHES=NOT_MEASURED
FULL_MODEL_PARITY=NOT_MEASURED
BLOCKER=PRODUCTION_QWEN4EXP_GRAPH_EXECUTOR_NOT_WIRED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
