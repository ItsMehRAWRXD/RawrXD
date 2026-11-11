# Gate 2 primary build/test integration receipt

Date: `2026-11-02`
Worktree: `F:\rawrxd`
HEAD: `2fcba4e60bcb8d5507134c2153c9245966de8602`

## Result

The authoritative `build_ide` CMake graph already declared the selected Gate 2 targets and CTest registrations, but the executable artifacts were absent before this run. The declared targets were built in place with MSVC/Ninja and then executed through the current `build_ide` CTest registry.

```ini
TARGET_BUILD=PASS
CTEST_EXIT=0
TESTS_SELECTED=7
TESTS_PASSED=6
TESTS_SKIPPED=1
TESTS_FAILED=0
```

Passed:

- `deep2_gpu_code31_pnp_probe`
- `deep2_gdn_reference_contract`
- `deep2_qwen4exp_operator_contract`
- `workspace_path_policy_smoke`
- `native_tool_protocol_smoke`
- `cursor_parity_registry_smoke`

Skipped by the test's own condition:

- `deep2_h11_prefill_parity`

## Scope boundary

This closes the isolated target-artifact integration gap for the selected Gate 2 set. It does not certify full Deep2 inference, GPU numerical parity, Kimi MLA, Phi-3 logits, or production promotion. The H11 parity test remains an explicit skipped condition, not a pass.

No source files were modified by this Gate 2 build/test run.

## Controlling state

```ini
GATE2_TARGET_INTEGRATION=PASS
GATE2_H11_PREFILL=SKIPPED
GATE2_FULL_PRIMITIVE_NUMERICAL_CERTIFICATION=OPEN
PROMOTE=0
CERTIFIED=0
```
