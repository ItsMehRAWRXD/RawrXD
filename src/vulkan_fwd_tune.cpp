// vulkan_fwd_tune.cpp — device workgroup tune + fused pool release
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE

namespace CPUInference {

bool VulkanCompute::TuneFromDevice() {
    if (kernel_tune_ok_) return true;
    if (!physical_device_) return false;
    VkPhysicalDeviceProperties p{};
    vkGetPhysicalDeviceProperties(physical_device_, &p);
    const uint32_t maxX = p.limits.maxComputeWorkGroupSize[0];
    gemv_local_size_ = 64;
    kernel_tune_ok_ = maxX >= 64;
    return kernel_tune_ok_;
}

void VulkanCompute::ReleaseFusedPool() {
    if (!device_) {
        fused_pool_ready_ = false;
        fused_cmd_ = nullptr;
        return;
    }
    fused_cmd_ = nullptr;
    for (uint32_t i = 0; i < 4; ++i) {
        if (fused_fence_[i]) {
            vkDestroyFence(device_, fused_fence_[i], nullptr);
            fused_fence_[i] = nullptr;
        }
        fused_pool_[i] = nullptr;
    }
    fused_pool_ready_ = false;
    fused_pool_i_ = 0;
    fused_cmd_idx_ = 0;
}

} // namespace CPUInference
#endif
