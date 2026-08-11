// vulkan_compute_stub.cpp - Minimal stub for VulkanCompute symbols
// Used when vulkan_compute.cpp cannot be compiled (e.g., missing std::expected)

#include <cstdint>
#include <vector>

namespace RawrXD {

enum class VulkanError { Success };

struct VulkanBuffer {
    uint64_t size = 0;
    void* hostPtr = nullptr;
};

class VulkanCompute {
public:
    VulkanCompute() = default;
    ~VulkanCompute() = default;

    struct ExpectedVoid {
        bool has_value() const { return true; }
        VulkanError error() const { return VulkanError::Success; }
    };

    ExpectedVoid initialize() { return {}; }
    ExpectedVoid executeMatrixMultiplication(const VulkanBuffer&, const VulkanBuffer&, VulkanBuffer&, uint64_t) { return {}; }
};

} // namespace RawrXD
