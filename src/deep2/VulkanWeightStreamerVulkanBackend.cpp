#include "VulkanWeightStreamerVulkanBackend.hpp"

#include <algorithm>

namespace Deep2 {

VulkanWeightStreamerVulkanBackend::VulkanWeightStreamerVulkanBackend(
    VulkanCompute* device, int quantType, uint64_t epoch) noexcept
    : device_(device), quantType_(quantType), epoch_(epoch) {}

VulkanWeightStreamerVulkanBackend::~VulkanWeightStreamerVulkanBackend() {
    // A scheduler should normally wait or reset before destruction. Drain any
    // leftover tickets so command buffers, fences, staging buffers, and device
    // allocations are not leaked if a caller abandons a stream.
    std::unordered_map<uint64_t, Pending> abandoned;
    {
        std::lock_guard<std::mutex> lock(mu_);
        abandoned.swap(pending_);
    }
    if (!device_) return;
    std::lock_guard<std::mutex> deviceLock(deviceMu_);
    for (auto& entry : abandoned) {
        auto& ticket = entry.second.ticket;
        if (ticket.submitted) (void)device_->WaitMaterialUpload(ticket);
    }
}

bool VulkanWeightStreamerVulkanBackend::submitCopy(
    const void* packed, size_t bytes, uint32_t logicalSlot,
    uint64_t signalValue) {
    (void)logicalSlot;
    if (!device_ || !packed || !bytes || !signalValue)
        return false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (pending_.find(signalValue) != pending_.end()) return false;
    }
    VulkanCompute::MaterialTicket ticket{};
    const uint64_t epoch = epoch_ ? epoch_ : device_->WorkEpoch();
    // SubmitWeightPrimeAsync records the real transfer command and fence. The
    // source pointer is retained only as a stable cache-key identity; the
    // upload itself copies into Vulkan-owned staging memory.
    {
        std::lock_guard<std::mutex> deviceLock(deviceMu_);
        if (!device_->SubmitWeightPrimeAsync(
                packed, bytes, quantType_,
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(packed)),
                epoch, ticket))
            return false;
    }
    std::lock_guard<std::mutex> lock(mu_);
    pending_.emplace(signalValue, Pending{ticket, packed, bytes});
    return true;
}

bool VulkanWeightStreamerVulkanBackend::wait(uint64_t signalValue) {
    Pending pending{};
    {
        std::lock_guard<std::mutex> lock(mu_);
        const auto it = pending_.find(signalValue);
        if (it == pending_.end()) return false;
        pending = it->second;
        pending_.erase(it);
    }

    bool ok = false;
    {
        std::lock_guard<std::mutex> deviceLock(deviceMu_);
        ok = device_->CommitWeightPrime(
            pending.ticket, quantType_,
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(pending.source)));
        // CommitWeightPrime owns the successful fence/ticket cleanup. If it
        // fails before adopting the target, perform the ordinary cleanup path.
        if (!ok && pending.ticket.submitted)
            (void)device_->WaitMaterialUpload(pending.ticket);
    }
    if (!ok) return false;
    std::lock_guard<std::mutex> lock(mu_);
    completed_ = (std::max)(completed_, signalValue);
    return true;
}

uint64_t VulkanWeightStreamerVulkanBackend::completedValue() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    return completed_;
}

} // namespace Deep2
