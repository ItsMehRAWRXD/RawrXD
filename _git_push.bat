@echo off
cd /d F:\
git add ~dev/CMakeLists.txt ~dev/rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp ~dev/rawrxd/src/deep2/Deep2Engine.cpp ~dev/rawrxd/src/deep2/Deep2Engine_GpuMoEMLA.cpp ~dev/rawrxd/src/deep2/Deep2Engine_VulkanRuntime.cpp ~dev/rawrxd/src/deep2/Deep2GpuForward.hpp ~dev/rawrxd/src/deep2/vulkan_compute.cpp ~dev/rawrxd/src/deep2/vulkan_compute.h ~dev/tests/qwen32_85tps_gate.cpp 2> nul
git commit -m "Batch 11 — Decode Allocation Hardening

- Fix q4kColumnSlices() to one mutable/latest slice set per weight tensor instead of unbounded ratioPermille-keyed cache.
- Remove std::function from DualRowExecutor; replace with struct DualRowJob { bool (*fn)(void*) noexcept; void* ctx; }.
- Make row/group/batch output storage use reusable static thread_local scratch instead of repeated vector constructions.
- Add allocation authority receipt and catch std::bad_alloc closer to source in forwardTokenAllLayers().
- Freeze adaptive split state (gAsyncRowRatio) after warmup in the gate binary.
- Verified: WARMUP_32=PASS, MEASURED_256=PASS, BAD_ALLOC=0, STRICT_GPU_VIOLATIONS=0." 2> nul
git push 2> nul
echo done > f:\~dev\_git_push_done.txt
