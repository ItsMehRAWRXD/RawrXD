// VwaGpuDma.hpp — runtime Vulkan H2D (NOT VWA authority)
#pragma once
#include <cstdint>
#include <cstddef>

namespace Deep2 {

struct GpuDmaWitness {
    uint64_t hostStageBytes = 0;
    uint64_t deviceStageBytes = 0;
    uint64_t gpuDmaBytes = 0;
    uint32_t uploadSubmits = 0;
    uint32_t uploadCompletions = 0;
    bool deviceObjectNonNull = false;
    bool realGpuDma = false;
    bool calledGpuApiInVwa = false;
    bool deviceSelectionInVwa = false;
};

// Opaque DEVICE_LOCAL buffer + owning Vulkan session slice.
void* GpuDma_AllocDevice(size_t bytes, GpuDmaWitness* w);
bool GpuDma_HostToDevice(const void* host, void* device, size_t bytes, GpuDmaWitness* w);
void GpuDma_FreeDevice(void* device);

} // namespace Deep2
