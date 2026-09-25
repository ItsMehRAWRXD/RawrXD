#pragma once
#include "ExpertCache.h"
#include "HostStagingRing.h"
#include <cstddef>
#include <cstdint>
#include <memory>

namespace rawrxd::deep2 {

struct VulkanExpertTransportConfig {
    void* physicalDevice = nullptr;   // VkPhysicalDevice from Deep2
    void* device = nullptr;           // VkDevice from Deep2
    void* queue = nullptr;            // VkQueue used for transfer/compute ordering
    void* commandPool = nullptr;      // VkCommandPool with RESET/FREE support
    uint32_t deviceOrdinal = 0;
    size_t stagingBytes = 64ull * 1024ull * 1024ull;
    size_t stagingAlignment = 256;
};

struct VulkanExpertTransportStats {
    uint64_t allocations = 0;
    uint64_t frees = 0;
    uint64_t submits = 0;
    uint64_t waits = 0;
    uint64_t pollsReady = 0;
    uint64_t submitFailures = 0;
    uint64_t bytesSubmitted = 0;
    uint64_t cpuExpertCompute = 0; // transport never increments this; certification field
    size_t stagingUsed = 0;
    size_t stagingCapacity = 0;
};

struct VulkanBufferBinding {
    uint64_t buffer = 0; // VkBuffer bit pattern; cast with your Vulkan ABI type
    uint64_t memory = 0; // VkDeviceMemory bit pattern
    size_t bytes = 0;
};

// Source-only Vulkan transport. On Windows it dynamically loads vulkan-1.dll;
// no Vulkan SDK headers or import library are required to compile this module.
class VulkanExpertTransport final {
public:
    static std::unique_ptr<VulkanExpertTransport> create(const VulkanExpertTransportConfig& cfg);
    ~VulkanExpertTransport();

    VulkanExpertTransport(const VulkanExpertTransport&) = delete;
    VulkanExpertTransport& operator=(const VulkanExpertTransport&) = delete;

    ExpertTransport callbacks();
    VulkanExpertTransportStats stats() const;
    bool binding(void* opaqueDeviceHandle, VulkanBufferBinding& out) const;
    bool ready() const noexcept;
    const char* lastError() const noexcept;

private:
    struct Impl;
    explicit VulkanExpertTransport(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::deep2
