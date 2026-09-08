// vulkan_fwd_q4k_act.cpp — DEVICE_LOCAL act arena + persistent host IO helpers
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <cstring>

namespace CPUInference {

bool VulkanCompute::EnsureGemvActDevice(size_t inBytes, size_t outBytes) {
    auto grow = [&](DeviceBuf& b, size_t need) -> bool {
        if (b.buffer && b.bytes >= need) return true;
        if (b.buffer) {
            vkDestroyBuffer(device_, b.buffer, nullptr);
            b.buffer = nullptr;
        }
        if (b.memory) {
            vkFreeMemory(device_, b.memory, nullptr);
            b.memory = nullptr;
        }
        b.bytes = 0;
        if (!CreateDeviceLocalBuffer(need, b.buffer, b.memory)) return false;
        b.bytes = need;
        return true;
    };
    return grow(gemv_act_in_, inBytes) && grow(gemv_act_out_, outBytes);
}

bool VulkanCompute::GemvHostWriteIn(const float* src, size_t bytes) {
    if (!src || !bytes || !gemv_in_mem_ || bytes > gemv_in_cap_) return false;
    void* mapped = nullptr;
    if (vkMapMemory(device_, gemv_in_mem_, 0, bytes, 0, &mapped) != VK_SUCCESS)
        return false;
    std::memcpy(mapped, src, bytes);
    vkUnmapMemory(device_, gemv_in_mem_);
    return true;
}

bool VulkanCompute::GemvHostReadOut(float* dst, size_t bytes) {
    if (!dst || !bytes || !gemv_out_mem_ || bytes > gemv_out_cap_) return false;
    void* mapped = nullptr;
    if (vkMapMemory(device_, gemv_out_mem_, 0, bytes, 0, &mapped) != VK_SUCCESS)
        return false;
    std::memcpy(dst, mapped, bytes);
    vkUnmapMemory(device_, gemv_out_mem_);
    return true;
}

} // namespace CPUInference
#endif
