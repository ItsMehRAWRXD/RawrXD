// vulkan_compute_stubs.cpp — Minimal stub implementations for VulkanCompute
// methods referenced by deep2_engine_lib when Vulkan SDK is unavailable.
// All methods return failure/default values so CPU inference can proceed.
#include <cstdint>
#include <vector>
#include <string>

namespace Deep2 {

struct VulkanCompute {
    struct DeviceBuf {};
    struct MaterialTicket {};
    struct GpuWorkInterval {};
    struct SpecOpsPush {};

    static std::vector<VulkanPhysicalInfo> EnumeratePhysicalDevices() { return {}; }

    bool initialize() { return false; }
    bool EnsureForwardArena(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) { return false; }
    bool DispatchGemvDevice(const float*, uint64_t, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t) { return false; }
    bool BeginFusedLayer() { return false; }
    bool EndFusedLayer() { return false; }
    bool ApplyWeightWindowPolicy(uint64_t, uint64_t, uint32_t, uint64_t) { return false; }
    bool CommitWeightPrime(MaterialTicket&, int, uint64_t, GpuWorkInterval*) { return false; }
    bool SubmitWeightPrimeAsync(const void*, uint64_t, int, uint64_t, uint64_t, MaterialTicket&) { return false; }
    bool WaitMaterialUpload(MaterialTicket&, GpuWorkInterval*) { return false; }
    ~VulkanCompute() {}
    VulkanCompute(uint32_t) {}
};

struct VulkanPhysicalInfo {};

// Additional VulkanCompute methods referenced by adapter code
bool VulkanCompute::DispatchGemvDeviceStrided(const float*, uint64_t, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, uint64_t) { return false; }
bool VulkanCompute::DispatchGemvQ4KBatch(const void*, uint64_t, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, uint32_t) { return false; }
bool VulkanCompute::WaitWeightCompute(uint32_t) { return false; }
bool VulkanCompute::SubmitGemvPrefetch(uint32_t, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, uint64_t, int) { return false; }
bool VulkanCompute::PrefetchWeight(const void*, uint64_t, uint32_t&) { return false; }
bool VulkanCompute::DispatchAttnDecode(DeviceBuf&, DeviceBuf&, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, uint32_t, uint32_t, float, uint32_t) { return false; }
bool VulkanCompute::AppendKV(DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, uint32_t) { return false; }
bool VulkanCompute::DispatchRope(DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, uint32_t, uint32_t, float) { return false; }
bool VulkanCompute::DispatchSwiGLU(DeviceBuf&, DeviceBuf&, DeviceBuf&, uint32_t) { return false; }
bool VulkanCompute::DispatchResidualAdd(DeviceBuf&, DeviceBuf&, DeviceBuf&, uint32_t) { return false; }
bool VulkanCompute::DispatchRmsNorm(DeviceBuf&, DeviceBuf&, DeviceBuf&, uint32_t, float) { return false; }
bool VulkanCompute::FlushWeightComputes() { return false; }
bool VulkanCompute::UploadNormWeight(DeviceBuf&, const float*, uint32_t) { return false; }
bool VulkanCompute::CopyArenaHiddenTo(VulkanCompute&, uint32_t) { return false; }
bool VulkanCompute::DownloadHidden(float*, uint32_t) { return false; }
bool VulkanCompute::UploadHidden(const float*, uint32_t) { return false; }

} // namespace Deep2
