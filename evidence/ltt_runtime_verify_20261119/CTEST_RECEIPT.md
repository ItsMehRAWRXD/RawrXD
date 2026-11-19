# Deep2/native regression run

COMMAND=ctest --test-dir build -C Release --output-on-failure -R "(deep2|native_action|gdn)"
PASSED=deep2_gpu_code31_pnp_probe;rawrxd_native_action_executor_test;deep2_gdn_reference_contract;deep2_qwen4exp_operator_contract;deep2_vulkan_gdn_dispatch;deep2_mla_lifecycle_test;deep2_attention_geometry_nan_regression
SKIPPED=deep2_h11_prefill_parity
BLOCKED=deep2_persistent_kv_smoke
BLOCKED_REASON=No completion within bounded observation window; process terminated
CERTIFICATION=HELD
