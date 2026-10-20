#include "VulkanWeightStreamer.hpp"

#include <algorithm>
#include <chrono>

namespace Deep2 {

VulkanWeightStreamer::VulkanWeightStreamer(IWeightTransferBackend* backend) noexcept
    : backend_(backend) {}

bool VulkanWeightStreamer::initialize(const WeightStreamConfig& config) {
    std::lock_guard<std::mutex> lock(mu_);
    config_ = config;
    initialized_ = config.enableAsyncTransfer && config.slotCount >= 1 &&
                   config.slotCount <= slots_.size() && config.vramBudgetBytes > 0 &&
                   config.stagingBudgetBytes > 0 &&
                   (!config.strictGpuExecution || backend_ != nullptr);
    nextTicket_ = 0;
    nextSignal_ = 0;
    nextAllocationEpoch_ = std::max<uint64_t>(1, nextAllocationEpoch_ + 1);
    resident_.clear();
    metrics_ = {};
    for (auto& slot : slots_) slot = {};
    cv_.notify_all();
    return initialized_;
}

void VulkanWeightStreamer::reset() noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    initialized_ = false;
    resident_.clear();
    for (auto& slot : slots_) slot = {};
    metrics_ = {};
    nextTicket_ = 0;
    nextSignal_ = 0;
    nextAllocationEpoch_ = std::max<uint64_t>(1, nextAllocationEpoch_ + 1);
    cv_.notify_all();
}

bool VulkanWeightStreamer::initialized() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    return initialized_;
}

VulkanWeightStreamer::Slot* VulkanWeightStreamer::lookupLocked(
    TransferTicket ticket) noexcept {
    if (!ticket.valid() || ticket.slot >= config_.slotCount) return nullptr;
    Slot& slot = slots_[ticket.slot];
    if (slot.ticketId != ticket.id || slot.generation != ticket.generation ||
        slot.allocationEpoch != ticket.allocationEpoch ||
        slot.signalValue != ticket.signalValue)
        return nullptr;
    return &slot;
}

const VulkanWeightStreamer::Slot* VulkanWeightStreamer::lookupLocked(
    TransferTicket ticket) const noexcept {
    if (!ticket.valid() || ticket.slot >= config_.slotCount) return nullptr;
    const Slot& slot = slots_[ticket.slot];
    if (slot.ticketId != ticket.id || slot.generation != ticket.generation ||
        slot.allocationEpoch != ticket.allocationEpoch ||
        slot.signalValue != ticket.signalValue)
        return nullptr;
    return &slot;
}

void VulkanWeightStreamer::noteStaleLocked() noexcept {
    ++metrics_.staleTickets;
}

TransferTicket VulkanWeightStreamer::prefetch(WeightTensorId tensor,
                                              const void* packed, size_t bytes) {
    if (!tensor || !packed || !bytes) return {};

    uint32_t slotIndex = std::numeric_limits<uint32_t>::max();
    TransferTicket ticket{};
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!initialized_ || !backend_ || bytes > config_.stagingBudgetBytes) {
            ++metrics_.failures;
            return {};
        }

        const auto hit = resident_.find(tensor);
        if (hit != resident_.end()) {
            const Slot& slot = slots_[hit->second];
            if (config_.enableExpertCache &&
                (slot.state == SlotState::Pending || slot.state == SlotState::Ready)) {
                ++metrics_.cacheHits;
                return {slot.ticketId, slot.generation, slot.allocationEpoch,
                        slot.signalValue, hit->second};
            }
            resident_.erase(hit);
        }

        ++metrics_.cacheMisses;
        if (config_.slotCount == 0 ||
            bytes > config_.vramBudgetBytes / config_.slotCount) {
            ++metrics_.failures;
            return {};
        }
        for (uint32_t i = 0; i < config_.slotCount; ++i) {
            if (slots_[i].state == SlotState::Empty ||
                slots_[i].state == SlotState::Failed) {
                slotIndex = i;
                break;
            }
        }
        if (slotIndex == std::numeric_limits<uint32_t>::max()) {
            ++metrics_.failures;
            return {};
        }

        Slot& slot = slots_[slotIndex];
        slot.state = SlotState::Pending;
        slot.tensor = tensor;
        slot.generation = std::max<uint64_t>(1, slot.generation + 1);
        slot.allocationEpoch = std::max<uint64_t>(1, ++nextAllocationEpoch_);
        slot.signalValue = ++nextSignal_;
        slot.ticketId = ++nextTicket_;
        slot.nextDispatchLease = 0;
        slot.dispatchLeases = 0;
        slot.bytes = bytes;
        resident_[tensor] = slotIndex;
        ticket = {slot.ticketId, slot.generation, slot.allocationEpoch,
                  slot.signalValue, slotIndex};
        ++metrics_.submitted;
        metrics_.bytesSubmitted += bytes;
        ++metrics_.inFlight;
    }

    if (!backend_->submitCopy(packed, bytes, slotIndex, ticket.signalValue)) {
        std::lock_guard<std::mutex> lock(mu_);
        if (Slot* slot = lookupLocked(ticket)) {
            slot->state = SlotState::Failed;
            resident_.erase(ticket.slot < config_.slotCount ? slot->tensor : 0);
            if (metrics_.inFlight) --metrics_.inFlight;
        }
        ++metrics_.failures;
        return {};
    }
    return ticket;
}

bool VulkanWeightStreamer::ready(TransferTicket ticket) const {
    std::lock_guard<std::mutex> lock(mu_);
    const Slot* slot = lookupLocked(ticket);
    return slot && slot->state == SlotState::Ready;
}

bool VulkanWeightStreamer::waitReady(TransferTicket ticket) {
    uint64_t signal = 0;
    {
        std::unique_lock<std::mutex> lock(mu_);
        Slot* slot = lookupLocked(ticket);
        if (!slot) { noteStaleLocked(); return false; }
        if (slot->state == SlotState::Ready) return true;
        if (slot->state != SlotState::Pending) return false;
        if (slot->waitInProgress) {
            cv_.wait(lock, [&] {
                Slot* current = lookupLocked(ticket);
                return !current || current->state != SlotState::Pending ||
                       !current->waitInProgress;
            });
            slot = lookupLocked(ticket);
            if (!slot) { noteStaleLocked(); return false; }
            return slot->state == SlotState::Ready;
        }
        slot->waitInProgress = true;
        signal = slot->signalValue;
        ++metrics_.waits;
    }

    const bool ok = backend_ && backend_->wait(signal);
    std::lock_guard<std::mutex> lock(mu_);
    Slot* slot = lookupLocked(ticket);
    if (!slot) { noteStaleLocked(); return false; }
    slot->waitInProgress = false;
    if (!ok) {
        slot->state = SlotState::Failed;
        resident_.erase(slot->tensor);
        if (metrics_.inFlight) --metrics_.inFlight;
        ++metrics_.failures;
        cv_.notify_all();
        return false;
    }
    if (slot->state == SlotState::Pending) {
        slot->state = SlotState::Ready;
        if (metrics_.inFlight) --metrics_.inFlight;
        ++metrics_.completed;
    }
    cv_.notify_all();
    return true;
}

bool VulkanWeightStreamer::bindResident(WeightTensorId tensor,
                                        ResidentBinding& out) const {
    std::lock_guard<std::mutex> lock(mu_);
    out = {};
    const auto it = resident_.find(tensor);
    if (it == resident_.end() || it->second >= config_.slotCount) return false;
    const Slot& slot = slots_[it->second];
    if (slot.state != SlotState::Ready) return false;
    out = {tensor, it->second, slot.generation, slot.allocationEpoch, 0,
           slot.bytes};
    return true;
}

bool VulkanWeightStreamer::acquireForDispatch(TransferTicket ticket,
                                              ResidentBinding& out) {
    std::lock_guard<std::mutex> lock(mu_);
    out = {};
    Slot* slot = lookupLocked(ticket);
    if (!slot || slot->state != SlotState::Ready) {
        if (!slot) noteStaleLocked();
        return false;
    }
    if (slot->dispatchLeases == std::numeric_limits<uint32_t>::max()) {
        ++metrics_.failures;
        return false;
    }
    ++slot->dispatchLeases;
    slot->nextDispatchLease = std::max<uint64_t>(1, slot->nextDispatchLease + 1);
    slot->activeDispatchLeases.insert(slot->nextDispatchLease);
    out = {slot->tensor, ticket.slot, slot->generation,
           slot->allocationEpoch, slot->nextDispatchLease, slot->bytes};
    return true;
}

bool VulkanWeightStreamer::releaseAfterGpuCompletion(ResidentBinding binding) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!binding.valid() || binding.slot >= config_.slotCount ||
        binding.dispatchLease == 0) return false;
    Slot& slot = slots_[binding.slot];
    if (slot.state != SlotState::Ready || slot.tensor != binding.tensor ||
        slot.generation != binding.generation ||
        slot.allocationEpoch != binding.allocationEpoch ||
        slot.dispatchLeases == 0 ||
        slot.activeDispatchLeases.find(binding.dispatchLease) ==
            slot.activeDispatchLeases.end()) {
        noteStaleLocked();
        return false;
    }
    slot.activeDispatchLeases.erase(binding.dispatchLease);
    --slot.dispatchLeases;
    return true;
}

bool VulkanWeightStreamer::release(ResidentBinding binding) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!binding.valid() || binding.slot >= config_.slotCount) return false;
    Slot& slot = slots_[binding.slot];
    if (slot.state != SlotState::Ready || slot.tensor != binding.tensor ||
        slot.generation != binding.generation ||
        slot.allocationEpoch != binding.allocationEpoch ||
        slot.dispatchLeases != 0) {
        noteStaleLocked();
        return false;
    }
    resident_.erase(binding.tensor);
    slot = {};
    return true;
}

uint32_t VulkanWeightStreamer::retireCompleted(uint64_t completedTimeline) {
    std::lock_guard<std::mutex> lock(mu_);
    // Do not promote a slot beyond the timeline the backend has actually
    // observed. A stale callback must never make an un-signalled copy look
    // resident.
    if (backend_) {
        completedTimeline = (std::min)(completedTimeline, backend_->completedValue());
    }
    uint32_t promoted = 0;
    for (uint32_t i = 0; i < config_.slotCount; ++i) {
        Slot& slot = slots_[i];
        if (slot.state == SlotState::Pending && slot.signalValue <= completedTimeline) {
            slot.state = SlotState::Ready;
            if (metrics_.inFlight) --metrics_.inFlight;
            ++metrics_.completed;
            ++promoted;
        }
    }
    if (promoted) cv_.notify_all();
    return promoted;
}

WeightStreamMetrics VulkanWeightStreamer::snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    return metrics_;
}

void VulkanWeightStreamer::emit(FILE* f) const {
    if (!f) f = stdout;
    const auto m = snapshot();
    const bool reached = initialized();
    const char* status = "NOT_RUN";
    if (m.failures) status = "FAIL";
    else if (m.submitted && m.completed == m.submitted) status = "PASS";
    else if (m.submitted) status = "OPEN";
    std::fprintf(f, "VWR_SOURCE_WIRED=1\n");
    std::fprintf(f, "VWR_RUNTIME_REACHED=%u\n", reached ? 1u : 0u);
    std::fprintf(f, "VWR_SUBMITTED=%llu\n", (unsigned long long)m.submitted);
    std::fprintf(f, "VWR_COMPLETED=%llu\n", (unsigned long long)m.completed);
    std::fprintf(f, "VWR_WAITS=%llu\n", (unsigned long long)m.waits);
    std::fprintf(f, "VWR_BYTES_SUBMITTED=%llu\n", (unsigned long long)m.bytesSubmitted);
    std::fprintf(f, "VWR_CACHE_HITS=%llu\n", (unsigned long long)m.cacheHits);
    std::fprintf(f, "VWR_CACHE_MISSES=%llu\n", (unsigned long long)m.cacheMisses);
    std::fprintf(f, "VWR_FAILURES=%llu\n", (unsigned long long)m.failures);
    std::fprintf(f, "VWR_STALE_TICKETS=%llu\n", (unsigned long long)m.staleTickets);
    std::fprintf(f, "VWR_IN_FLIGHT=%llu\n", (unsigned long long)m.inFlight);
    std::fprintf(f, "VWR_STATUS=%s\n", status);
    std::fprintf(f, "NOT_RUN!=PASS\n");
    std::fflush(f);
}

} // namespace Deep2
