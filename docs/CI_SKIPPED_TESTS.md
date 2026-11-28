# Skipped CTest cases — investigation

Baseline: 89 registered tests, 2 skipped, 1 failed.

## #7 deep2_h11_prefill_parity

- Definition: `CMakeLists.txt:3938-3965`.
- Command: `deep2_h11_prefill_parity $ENV{DEEP2_H11_MODEL}`.
- Skip mechanism: `SKIP_RETURN_CODE 77`.
- Root cause: `DEEP2_H11_MODEL` is unset in the local and CI environments, so the
  harness returns 77 (self-skip) rather than running without a model.
- Closure: set `DEEP2_H11_MODEL` to a real on-disk GGUF and run on the product
  preset. This is a model-availability gate, not a disabled test.
- Status: OPEN (requires model selection).

## #73 deep2_persistent_kv_smoke

- Definition: `CMakeLists.txt:7015-7033`.
- Command: `deep2_persistent_kv_smoke`.
- Skip mechanism: `SKIP_RETURN_CODE 77`, `TIMEOUT 60`.
- Root cause: the smoke harness returns 77 when no usable model/backend is
  present; it is a runtime capability gate.
- Closure: run on a machine with a resident model and the Vulkan backend, or
  provide the model path the harness expects.
- Status: OPEN (requires model/backend availability).

## Policy

These tests must not be removed or converted to unconditional pass. Closing them
requires real model execution evidence, recorded in the configuration ledger.