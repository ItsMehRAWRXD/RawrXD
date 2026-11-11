# RawrXD end-to-end completion audit

This is a fail-closed inventory, not a certification receipt.

## Explicit production-path blockers

| Path | Current behavior | Required closure |
|---|---|---|
| `src/deep2/vulkan_compute.cpp::DispatchGdn` | Returns `false`; executor uses CPU GDN fallback | Implement and numerically certify stateful Vulkan GDN, or keep GPU admission disabled |
| `src/deep2/vulkan_compute.cpp::ResetGdnState` | No device state exists because GPU GDN is disabled | Add state ownership/cleanup with lifecycle tests when dispatch is implemented |
| `src/deep2/Deep2Engine.cpp` Qwen3.6 full path | Finite CPU output, final hidden/logit parity fails against native oracle | Capture compatible per-layer reference tensors and repair the first proven divergence |
| Native llama.cpp oracle API | Exposes final logits/final state only in installed build | Build/use a debug-capable reference for per-layer residuals |
| IDE product promotion | Runtime and GhostText gates are not all current-binary certified | Re-run current executable GUI/agent/GhostText matrix after source closure |

## Verified in this audit

- Qwen3.6 CPU GDN intermediate parity remains PASS within its existing scope.
- Native llama.cpp oracle loads the exact GGUF and emits 248,320 finite logits.
- Deep2 final hidden/logit vectors diverge materially from the native oracle.
- Deep2 boundary captures are deterministic: 160/160 repeated hashes match.
- Diagnostic Deep2 rebuild completed with zero linker errors.

```ini
PROMOTE=0
GPU_GDN=FAIL_CLOSED
FULL_MODEL_PARITY=FAIL
FIRST_DIVERGENT_LAYER=UNKNOWN
IDE_END_TO_END=NOT_CERTIFIED
```
