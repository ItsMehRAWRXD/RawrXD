# BUILD_SURFACE_REVIEW

ASOF_UTC=2026-11-02T12:38:40.6858153Z
FILE=CMakeLists.txt
DECISION=HOLD_INSPECT
COMMIT=0
WORKING_SHA256=E6DE4AEF75967CA73ABC5E5995039D5B760CF548119F0BC47CA9933349C3866C
HEAD_BLOB=e7214b943897c6bee103d6a4418f8e6d186667ce

## Diffstat
```
 CMakeLists.txt | 76 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 76 insertions(+)
```

## Diff (first 120 lines)
```
diff --git a/CMakeLists.txt b/CMakeLists.txt
index e7214b9438..b69b415ce4 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1780,7 +1780,13 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_parity_trace.cpp" AND EXISTS "${CMAKE
         # hand-rolled tools/build_deep2_parity_trace.bat compiles, so the
         # CMake target and the bat now share ONE definition of the build.
         src/deep2/quant_dot_dispatch.cpp
+        src/deep2/lavapath/GpuDeviceLostReset.cpp
+        src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
+        src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
+        src/deep2/lavapath/GpuDeviceLostReset.cpp
         src/vulkan_compute.cpp
+        src/vulkan_compute_attn.cpp
+        src/vulkan_compute_attn.cpp
         src/streaming_gguf_loader.cpp
         src/gguf_loader.cpp
         src/gguf_vocab_resolver.cpp
@@ -1841,6 +1847,7 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_bench_tps.cpp" AND
         src/deep2/op_gdn.cpp
         src/deep2/modelgenie/universal_gguf.cpp
         src/deep2/quant_dot_dispatch.cpp
+        src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
         src/deep2/lavapath/GpuDeviceLostReset.cpp
         src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
         src/vulkan_compute.cpp
@@ -1901,6 +1908,8 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_gpu_certify.cpp" AND EXISTS "${CMAKE_
         src/deep2/op_linear.cpp
         src/deep2/modelgenie/universal_gguf.cpp
         src/deep2/quant_dot_dispatch.cpp
+        src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
+        src/deep2/lavapath/GpuDeviceLostReset.cpp
         # The executor's stateful GDN path uses the Deep2 VulkanCompute
         # implementation (separate from the legacy quant-dot wrapper below).
         # Keep both translation units: quant_dot_dispatch.cpp intentionally
@@ -1910,6 +1919,7 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_gpu_certify.cpp" AND EXISTS "${CMAKE_
         src/deep2/QuantKernelRegistry.cpp
         src/deep2/asm_stubs.cpp
         src/vulkan_compute.cpp
+        src/vulkan_compute_attn.cpp
         src/streaming_gguf_loader.cpp
         src/gguf_loader.cpp
         src/gguf_vocab_resolver.cpp
@@ -2350,11 +2360,14 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_d1_prefill_parity.cpp" AND EXISTS "${
         src/deep2/op_linear.cpp
         src/deep2/modelgenie/universal_gguf.cpp
         src/deep2/quant_dot_dispatch.cpp
+        src/deep2/lavapath/GpuDeviceLostReset.cpp
+        src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
         src/deep2/QuantKernelRegistry.cpp
         src/deep2/asm_stubs.cpp
         src/deep2/vulkan_compute.cpp
         src/deep2/op_gdn.cpp
         src/vulkan_compute.cpp
+        src/vulkan_compute_attn.cpp
         src/streaming_gguf_loader.cpp
         src/gguf_loader.cpp
         src/gguf_vocab_resolver.cpp
@@ -2410,12 +2423,15 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_spec_bench.cpp" AND EXISTS "${CMAKE_S
         src/deep2/op_linear.cpp
         src/deep2/modelgenie/universal_gguf.cpp
         src/deep2/quant_dot_dispatch.cpp
+        src/deep2/lavapath/GpuDeviceLostReset.cpp
+        src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
         src/deep2/QuantKernelRegistry.cpp
         src/deep2/asm_stubs.cpp
         src/deep2/deep2_speculative.cpp
         src/deep2/vulkan_compute.cpp
         src/deep2/op_gdn.cpp
         src/vulkan_compute.cpp
+        src/vulkan_compute_attn.cpp
         src/streaming_gguf_loader.cpp
         src/gguf_loader.cpp
         src/gguf_vocab_resolver.cpp
@@ -2576,11 +2592,14 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_context_scaling.cpp" AND EXISTS "${CM
         src/deep2/op_linear.cpp
         src/deep2/modelgenie/universal_gguf.cpp
         src/deep2/quant_dot_dispatch.cpp
+        src/deep2/lavapath/GpuDeviceLostReset.cpp
+        src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
         src/deep2/QuantKernelRegistry.cpp
         src/deep2/asm_stubs.cpp
         src/deep2/vulkan_compute.cpp
         src/deep2/op_gdn.cpp
         src/vulkan_compute.cpp
+        src/vulkan_compute_attn.cpp
         src/streaming_gguf_loader.cpp
         src/gguf_loader.cpp
         src/gguf_vocab_resolver.cpp
@@ -2635,11 +2654,14 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_gguf_lifecycle.cpp" AND EXISTS "${CMA
         src/deep2/op_linear.cpp
         src/deep2/modelgenie/universal_gguf.cpp
         src/deep2/quant_dot_dispatch.cpp
+        src/deep2/lavapath/GpuDeviceLostReset.cpp
+        src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
         src/deep2/QuantKernelRegistry.cpp
         src/deep2/asm_stubs.cpp
         src/deep2/vulkan_compute.cpp
         src/deep2/op_gdn.cpp
         src/vulkan_compute.cpp
+        src/vulkan_compute_attn.cpp
         src/streaming_gguf_loader.cpp
         src/gguf_loader.cpp
         src/gguf_vocab_resolver.cpp
@@ -3001,11 +3023,14 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_agentic_repair.cpp" AND EXISTS "${CMA
         src/deep2/op_linear.cpp
         src/deep2/modelgenie/universal_gguf.cpp
         src/deep2/quant_dot_dispatch.cpp
+        src/deep2/lavapath/GpuDeviceLostReset.cpp
+        src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp
         src/deep2/QuantKernelRegistry.cpp
         src/deep2/asm_stubs.cpp
         src/deep2/vulkan_compute.cpp
         src/deep2/op_gdn.cpp
         src/vulkan_compute.cpp
+        src/vulkan_compute_attn.cpp
         src/streaming_gguf_loader.cpp
         src/gguf_loader.cpp
         src/gguf_vocab_resolver.cpp
@@ -3117,11 +3142,14 @@ if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_prefill_parity.cpp" AND EXISTS "${CMA
```

## Native product target notes (from audit)
- Authority product path: RawrXD-Win32IDE-Native (RAWRXD_BUILD_WIN32IDE=ON)
- Qt RawrXD-Win32IDE: OFF by default / LEGACY
- Dirty CMakeLists must not silently alter seal inputs; treat as HOLD until reviewed
- Any candidate build must pin exact CMake options in the candidate manifest
