#pragma once
/* vulkan_compute — stub */
#include <cstdint>
#include <cstddef>
namespace Deep2 {
struct GpuBuffer { uint64_t id = 0; };
class VulkanCompute {
public:
    struct DeviceBuf { uint64_t id = 0; size_t size = 0; };
    static size_t ForwardArenaReserveBytes(int /*device*/) { return 0; }
    bool initialize() { return true; }
    void submit() {}
    bool UploadNormWeight(DeviceBuf, const float*, size_t) { return true; }
    bool FlushWeightComputes() { return true; }
    bool PrefetchWeight(const void*, size_t, uint32_t&) { return true; }
    bool SubmitGemvPrefetch(uint32_t, DeviceBuf, DeviceBuf, uint32_t, uint32_t, size_t = 0, int = 0) { return true; }
    bool DispatchGemvQuant(int, const void*, size_t, DeviceBuf, DeviceBuf, uint32_t, uint32_t) { return true; }
    bool DispatchGemvDevice(const float*, uint64_t, DeviceBuf, DeviceBuf, uint32_t, uint32_t) { return true; }
    bool WeightStreamActive() { return false; }
    bool WeightPrefetchActive() { return false; }
    DeviceBuf ArenaAttnW() { return {}; }
    DeviceBuf ArenaFfnW() { return {}; }
    DeviceBuf ArenaQ() { return {}; }
    DeviceBuf ArenaK() { return {}; }
    DeviceBuf ArenaV() { return {}; }
    DeviceBuf ArenaO() { return {}; }
    DeviceBuf ArenaGate() { return {}; }
    DeviceBuf ArenaUp() { return {}; }
    DeviceBuf ArenaDown() { return {}; }
};
} // namespace Deep2
namespace CPUInference { using VulkanCompute = Deep2::VulkanCompute; }

