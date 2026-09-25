#include "GPUBackend.hpp"
#include <mutex>
#include <map>
#include <stdexcept>

namespace rawrxd::gpu {

// ───────────────────────────────────────────────────────────────
// GPUBackend base implementation (device-agnostic logic)
// ───────────────────────────────────────────────────────────────
GPUBackend::GPUBackend() = default;
GPUBackend::~GPUBackend() = default;

std::unique_ptr<GPUBackend> GPUBackend::Create(GPUBackendType type) {
    // Factory: concrete implementations would be registered here
    // For now, return nullptr (actual backends linked externally)
    (void)type;
    return nullptr;
}

std::vector<GPUBackendType> GPUBackend::GetAvailableBackends() {
    std::vector<GPUBackendType> available;
    // Runtime detection would check for Vulkan/CUDA/Metal/etc.
    available.push_back(GPUBackendType::Vulkan);
    return available;
}

} // namespace rawrxd::gpu
