// VulkanWeightStreamer.hpp — fail-closed asynchronous weight residency scheduler
//
// This component owns the lifetime contract around an asynchronous transfer
// backend.  It deliberately does not issue Vulkan calls itself: the backend is
// required to provide the real queue submission, timeline wait, and completion
// operations.  That keeps the scheduler testable while preventing a CPU-only
// stub from being reported as GPU residency.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <mutex>
#include <unordered_map>

namespace Deep2 {

using WeightTensorId = uint64_t;

struct WeightStreamConfig {
    uint64_t vramBudgetBytes = 20ull << 30;
    uint64_t stagingBudgetBytes = 512ull << 20;
    uint32_t slotCount = 2;
    bool enableAsyncTransfer = true;
    bool enableExpertCache = true;
    bool enablePredictivePrefetch = true;
    bool strictGpuExecution = true;
};

struct TransferTicket {
    uint64_t id = 0;
    uint64_t generation = 0;
    uint64_t signalValue = 0;
    uint32_t slot = std::numeric_limits<uint32_t>::max();

    bool valid() const noexcept {
        return id != 0 && generation != 0 && signalValue != 0 &&
               slot != std::numeric_limits<uint32_t>::max();
    }
};

struct ResidentBinding {
    WeightTensorId tensor = 0;
    uint32_t slot = std::numeric_limits<uint32_t>::max();
    uint64_t generation = 0;
    uint64_t bytes = 0;

    bool valid() const noexcept {
        return tensor != 0 && generation != 0 &&
               slot != std::numeric_limits<uint32_t>::max();
    }
};

// The production adapter must connect these calls to actual Vulkan transfer
// submission and a timeline semaphore.  A null backend is intentionally not a
// usable runtime: strictGpuExecution therefore fails initialization closed.
class IWeightTransferBackend {
public:
    virtual ~IWeightTransferBackend() = default;
    virtual bool submitCopy(const void* packed, size_t bytes,
                            uint32_t logicalSlot, uint64_t signalValue) = 0;
    virtual bool wait(uint64_t signalValue) = 0;
    virtual uint64_t completedValue() const noexcept = 0;
};

struct WeightStreamMetrics {
    uint64_t submitted = 0;
    uint64_t completed = 0;
    uint64_t waits = 0;
    uint64_t bytesSubmitted = 0;
    uint64_t cacheHits = 0;
    uint64_t cacheMisses = 0;
    uint64_t failures = 0;
    uint64_t staleTickets = 0;
    uint64_t inFlight = 0;
};

class VulkanWeightStreamer {
public:
    explicit VulkanWeightStreamer(IWeightTransferBackend* backend = nullptr) noexcept;

    bool initialize(const WeightStreamConfig& config);
    void reset() noexcept;
    bool initialized() const noexcept;
    const WeightStreamConfig& config() const noexcept { return config_; }

    TransferTicket prefetch(WeightTensorId tensor, const void* packed,
                            size_t bytes);
    bool waitReady(TransferTicket ticket);
    bool bindResident(WeightTensorId tensor, ResidentBinding& out) const;
    bool release(ResidentBinding binding);

    // Polling completion is non-blocking.  It promotes all pending tickets up
    // to the supplied backend timeline value and never retires live bindings.
    uint32_t retireCompleted(uint64_t completedTimeline);

    WeightStreamMetrics snapshot() const noexcept;
    void emit(FILE* f) const;

private:
    enum class SlotState : uint8_t { Empty, Pending, Ready, Failed };
    struct Slot {
        SlotState state = SlotState::Empty;
        WeightTensorId tensor = 0;
        uint64_t generation = 0;
        uint64_t signalValue = 0;
        uint64_t ticketId = 0;
        uint64_t bytes = 0;
    };

    Slot* lookupLocked(TransferTicket ticket) noexcept;
    const Slot* lookupLocked(TransferTicket ticket) const noexcept;
    void noteStaleLocked() noexcept;

    IWeightTransferBackend* backend_ = nullptr;
    WeightStreamConfig config_{};
    bool initialized_ = false;
    uint64_t nextTicket_ = 0;
    uint64_t nextSignal_ = 0;
    std::array<Slot, 16> slots_{};
    std::unordered_map<WeightTensorId, uint32_t> resident_;
    mutable std::mutex mu_;
    WeightStreamMetrics metrics_{};
};

} // namespace Deep2
