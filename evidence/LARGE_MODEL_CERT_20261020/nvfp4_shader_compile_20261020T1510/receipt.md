# NVFP4 shader compile receipt — 2026-10-20

Status: **PASS (shader artifact); runtime integration OPEN**

The corrected NVFP4 GLSL source at
`src/deep2/shaders/deep2_qgemv_nvfp4.comp` compiles with:

```
C:\VulkanSDK\1.4.357.0\Bin\glslc.exe -O --target-env=vulkan1.2 \
  src/deep2/shaders/deep2_qgemv_nvfp4.comp \
  -o src/deep2/shaders/deep2_qgemv_nvfp4.spv
```

The generated SPIR-V is 5,268 bytes with SHA-256
`5038B0DDB098F6FFD507D3327896948367E1108451AED422A889E758336659DA`.

This closes the GLSL type-check/compile defect in `e4m3_to_fp32`. It does not
close the NVFP4 inference gate: the benchmark's active top-level
`include/vulkan_compute.h` / `src/vulkan_compute.cpp` path still accepts
quant-dot kinds 0–6, while NVFP4 is kind 7. The shader is therefore preserved
as a verified artifact pending dispatcher and descriptor-layout integration,
GPU/CPU parity, and a rerun of the Nemotron-Bolt smoke.
