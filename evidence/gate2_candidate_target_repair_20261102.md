# Gate 2 candidate target integration

Date: 2026-11-02
Build tree: `F:/rawrxd/build_ghosttext_boundary`

## Targets built

The following CTest-registered targets were missing from the isolated build output and were built successfully with MSVC:

- `deep2_gpu_code31_pnp_probe`
- `deep2_gdn_parity_harness`
- `deep2_qwen4exp_operator_harness`
- `deep2_h11_prefill_parity`
- `workspace_path_policy_smoke`
- `native_tool_protocol_smoke`
- `cursor_parity_registry_smoke`

Build exit: `0`.

## CTest result

Selected smoke run:

```ini
TESTS_SELECTED=6
TESTS_PASSED=5
TESTS_SKIPPED=1
TESTS_FAILED=0
CTEST_EXIT=0
```

Passed tests: `deep2_gpu_code31_pnp_probe`, `deep2_qwen4exp_operator_contract`, `workspace_path_policy_smoke`, `native_tool_protocol_smoke`, `cursor_parity_registry_smoke`.

Skipped: `deep2_h11_prefill_parity` (test-defined skip condition).

Additional contract run: `deep2_gpu_code31_pnp_probe`, `deep2_gdn_reference_contract`, and `deep2_qwen4exp_operator_contract` passed; `deep2_h11_prefill_parity` remained skipped; exit `0`.

This closes the isolated target-wiring defect for the selected Gate 2 set. It does not certify full Deep2 inference, GPU numerical parity, REAP, or production promotion.
