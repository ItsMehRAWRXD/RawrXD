// Deep2ComputeAbi.hpp — backend-agnostic compute surface (transformer talks here)
#pragma once
#include <cstddef>
#include <cstdint>

namespace Deep2 {

// Backends under this ABI (implementations may be absent on a given build):
//   CPU_NATIVE | VULKAN | CUDA | HIP | DIRECTML | UMA_SHARED
enum class ComputeBackend : uint8_t {
    CpuNative = 0,
    Vulkan = 1,
    Cuda = 2,
    Hip = 3,
    DirectMl = 4,
    UmaShared = 5,
};

struct ComputeBufferHandle {
    uint64_t id = 0;
    uint64_t bytes = 0;
    int deviceIndex = -1;  // plan.adapters[] index; -1 = host
};

// Lifecycle (Vulkan today; others later):
//   Deep2Device_Open → buffers/kernels → Deep2Device_Close
// Transformer code must not branch on vendor names.

} // namespace Deep2
