// vulkan_fwd_hostops.cpp — ExecuteRMSNorm / ExecuteSiLU on resident arena
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <vector>

namespace CPUInference {

bool VulkanCompute::ExecuteRMSNorm(float* data, uint32_t size, float epsilon) {
    if (!data || size == 0) return false;
    if (!EnsureForwardArena(size, size, 1, 1, 1, 1, 1)) return false;
    std::vector<float> ones(size, 1.0f);
    if (!UploadHidden(data, size)) return false;
    if (!UploadNormWeight(ArenaAttnW(), ones.data(), size)) return false;
    if (!DispatchRmsNorm(ArenaHidden(), ArenaAttnW(), ArenaNormed(), size, epsilon))
        return false;
    return DownloadDeviceLocal(fwd_normed_.buffer, data, (size_t)size * 4);
}

bool VulkanCompute::ExecuteSiLU(float* data, uint32_t size) {
    if (!data || size == 0) return false;
    if (!EnsureForwardArena(size, size, 1, 1, 1, 1, 1)) return false;
    std::vector<float> ones(size, 1.0f);
    if (!UploadToDeviceLocal(data, (size_t)size * 4, fwd_gate_.buffer)) return false;
    if (!UploadToDeviceLocal(ones.data(), (size_t)size * 4, fwd_up_.buffer)) return false;
    if (!DispatchSwiGLU(ArenaGate(), ArenaUp(), ArenaFFNAct(), size)) return false;
    return DownloadDeviceLocal(fwd_ffn_act_.buffer, data, (size_t)size * 4);
}

bool VulkanCompute::DownloadBuf(DeviceBuf& b, float* host, uint32_t n) {
    if (!b.buffer || !host || n == 0) return false;
    return DownloadDeviceLocal(b.buffer, host, (size_t)n * 4);
}

bool VulkanCompute::UploadBuf(DeviceBuf& b, const float* host, uint32_t n) {
    if (!b.buffer || !host || n == 0) return false;
    return UploadToDeviceLocal(host, (size_t)n * 4, b.buffer);
}

} // namespace CPUInference
#endif
