@echo off
cd /d F:\
git add ~dev/CMakeLists.txt ~dev/rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp ~dev/rawrxd/src/deep2/Deep2Engine.cpp ~dev/rawrxd/src/deep2/Deep2Engine_GpuMoEMLA.cpp ~dev/rawrxd/src/deep2/Deep2Engine_VulkanRuntime.cpp ~dev/rawrxd/src/deep2/Deep2GpuForward.hpp ~dev/rawrxd/src/deep2/vulkan_compute.cpp ~dev/rawrxd/src/deep2/vulkan_compute.h ~dev/tests/qwen32_85tps_gate.cpp > nul 2>&1
git status --short > f:\~dev\_git_status_out.txt 2>&1
git diff --cached --stat > f:\~dev\_git_diffstat_out.txt 2>&1
echo done > f:\~dev\_git_done.txt
