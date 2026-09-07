// VwaGpuStageBridge.hpp — runtime host→device staging (NOT VWA DMA authority)
#pragma once
#include "VwaGpuDma.hpp"
#include <cstdint>

namespace Deep2 {

using GpuStageWitness = GpuDmaWitness;

inline void* RuntimeAllocDeviceStage(size_t n, GpuStageWitness* w = nullptr) {
    return GpuDma_AllocDevice(n, w);
}

inline void RuntimeFreeDeviceStage(void* p) { GpuDma_FreeDevice(p); }

inline bool RuntimeHostToDeviceStage(const void* host, void* device, size_t n,
                                     GpuStageWitness* w = nullptr) {
    return GpuDma_HostToDevice(host, device, n, w);
}

} // namespace Deep2
