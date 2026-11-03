# RAWRXD_CONTINUATION_001

## Build and regression result

The full `build_reap` target set was rebuilt from a VS2022 x64 developer environment after repairing missing CMake source wiring for Deep2 Vulkan certification targets.

```ini
FULL_BUILD=PASS
LINK_ERRORS=0
CTEST_EXIT=0
CTEST_EXECUTED=26
CTEST_PASSED=26
CTEST_SKIPPED=1
CTEST_FAILED=0
PROMOTE=0
```

## CMake integration repaired

Targets that previously omitted required translation units now include the Vulkan attention and GPU-reset implementations:

- `src/vulkan_compute_attn.cpp`
- `src/deep2/lavapath/GpuDeviceLostReset.cpp`
- `src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp`

This repaired unresolved externals in `deep2_gpu_certify`, `deep2_gguf_lifecycle`, `deep2_d1_prefill_parity`, `deep2_spec_bench`, `deep2_context_scaling`, `deep2_agentic_repair`, and `deep2_prefill_parity`.

The one skipped test, `deep2_h11_prefill_parity`, remains an intentional CTest skip and is not counted as a pass.

Raw output: `ctest_latest.log`; build output: `full_build_latest.log`.
