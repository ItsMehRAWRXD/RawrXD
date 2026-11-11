# Deep2 GDN production-dispatch wiring

Date: 2026-11-02
Worktree: `F:\rawrxd`
HEAD at audit start: `2fcba4e60bcb`

## Production path

- `src/deep2/runtime_graph_executor.cpp` calls `Deep2::VulkanCompute::DispatchGdn` when the executor is not forced to CPU.
- `src/deep2/vulkan_compute.cpp` owns the Vulkan GDN descriptor set, pipeline, device-state map, upload/dispatch/download sequence, and reset lifecycle.
- `src/deep2/shaders/deep2_qwen4exp_gdn.spv` is loaded by `VulkanCompute::createPipelines()`.
- `src/deep2/op_gdn.cpp` supplies the independent Qwen recurrence reference.

## Target ownership repair

`rawrxd_gpu_compute` now owns these real implementation translation units:

- `src/deep2/vulkan_compute.cpp`
- `src/deep2/QuantKernelRegistry.cpp`
- `src/deep2/asm_stubs.cpp`
- `src/deep2/lavapath/GpuDeviceLostReset.cpp`
- `src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp`

The probe initially failed to link because `QuantKernelRegistry.cpp` referenced
`Deep2::RegisterIQKernels()` and `Deep2_FP16_GEMV` without its existing owner.
The CMake repair adds `asm_stubs.cpp`; no test-only symbol or replacement
implementation was introduced.

## Contract repair

The device shader applies the Qwen query scale and normalization epsilon. The
CPU reference now consumes the same descriptor fields. The runtime descriptor
sets the production Qwen scale to `1/sqrt(head_dim)` instead of leaving the
generic default `1.0` in place.

