// VulkanWeightStreamerVulkanBackend.hpp — adapter to the real Deep2 upload lane
#pragma once

#include "VulkanWeightStreamer.hpp"
#include "vulkan_compute.h"

#include <mutex>
#include <unordered_map>

namespace Deep2 {

// This adapter is intentionally separate from VulkanWeightStreamer. The
// scheduler owns slot/ticket lifetime; this class owns the real Vulkan material
// upload ticket and adopts the completed buffer into Deep2's weight cache.
class VulkanWeightStreamerVulkanBackend final : public IWeightTransferBackend {
public:
    VulkanWeightStreamerVulkanBackend(VulkanCompute* device, int quantType,
                                      uint64_t epoch = 0) noexcept;
    ~VulkanWeightStreamerVulkanBackend() override;

    bool submitCopy(const void* packed, size_t bytes, uint32_t logicalSlot,
                    uint64_t signalValue) override;
    bool wait(uint64_t signalValue) override;
    uint64_t completedValue() const noexcept override;

private:
    struct Pending {
        VulkanCompute::MaterialTicket ticket{};
        const void* source = nullptr;
        size_t bytes = 0;
    };

    VulkanCompute* device_ = nullptr;
    int quantType_ = 0;
    uint64_t epoch_ = 0;
    mutable std::mutex mu_;
    std::mutex deviceMu_;
    std::unordered_map<uint64_t, Pending> pending_;
    uint64_t completed_ = 0;
};

} // namespace Deep2
