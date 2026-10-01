// ============================================================================
// Deep2ReadyRing.cpp
// RAWRXD_DEEP2_BOUNDED_STREAM_001
// See Deep2ReadyRing.hpp for the invariant contract.
// ============================================================================

#include "Deep2ReadyRing.hpp"

namespace Deep2 {

uint32_t ReadyRing::indexOf(const ReadyWork* work) const noexcept {
    if (!work) return Capacity;

    // The record must physically live inside this ring's slot array, and the
    // slotIndex it carries must agree with where the record actually is. Both
    // are checked because either one alone can be satisfied by a stale or
    // foreign handle.
    const auto* base = reinterpret_cast<const char*>(&slots_[0]);
    const auto* rec = reinterpret_cast<const char*>(work);
    if (rec < base) return Capacity;

    const size_t offset = static_cast<size_t>(rec - base);
    if (offset % sizeof(Slot) != 0) return Capacity;

    const uint32_t idx = static_cast<uint32_t>(offset / sizeof(Slot));
    if (idx >= Capacity) return Capacity;
    if (&slots_[idx].work != work) return Capacity;
    if (work->slotIndex != idx) return Capacity;
    return idx;
}

bool ReadyRing::reserveProducer(ReadyWork*& work) noexcept {
    nReserveAttempts_.fetch_add(1, std::memory_order_relaxed);
    work = nullptr;

    // Relaxed: the producer owns this cursor, and the ordering that matters is
    // carried by the per-slot state CAS below.
    const uint64_t head = producer_.load(std::memory_order_relaxed);
    Slot& slot = slots_[head % Capacity];

    ReadyState expected = ReadyState::Empty;
    // Acquire pairs with the consumer's release store in releaseConsumer, so
    // the producer observes every read the consumer made of this slot before
    // overwriting it.
    if (!slot.state.compare_exchange_strong(expected, ReadyState::Filling,
                                            std::memory_order_acquire,
                                            std::memory_order_relaxed)) {
        nReserveFailures_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Identity is stamped here, before the caller can see the record, so
    // publish/cancel never depend on pointer arithmetic.
    slot.work = ReadyWork{};
    slot.work.slotIndex = static_cast<uint32_t>(head % Capacity);
    work = &slot.work;
    return true;
}

bool ReadyRing::publishProducer(ReadyWork* work) noexcept {
    const uint32_t idx = indexOf(work);
    if (idx == Capacity) {
        nBadHandles_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // A slot must not become consumable unless the payload is actually
    // consumable. Residency failure stays on the producer side.
    if (!work->weights || work->weightBytes == 0) {
        nPublishRefusals_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    Slot& slot = slots_[idx];
    // Release: every field written above is visible to a consumer that
    // acquires this slot with acquire semantics.
    slot.state.store(ReadyState::Ready, std::memory_order_release);
    producer_.fetch_add(1, std::memory_order_relaxed);
    nPublishes_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void ReadyRing::cancelProducer(ReadyWork* work) noexcept {
    const uint32_t idx = indexOf(work);
    if (idx == Capacity) {
        nBadHandles_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // No cursor advance. Skipping a sequence number here would leave the
    // consumer waiting forever on a slot that is never published.
    slots_[idx].state.store(ReadyState::Empty, std::memory_order_release);
    nCancels_.fetch_add(1, std::memory_order_relaxed);
}

bool ReadyRing::acquireConsumer(const ReadyWork*& work) noexcept {
    nAcquireAttempts_.fetch_add(1, std::memory_order_relaxed);
    work = nullptr;

    const uint64_t tail = consumer_.load(std::memory_order_relaxed);
    Slot& slot = slots_[tail % Capacity];

    ReadyState expected = ReadyState::Ready;
    if (!slot.state.compare_exchange_strong(expected, ReadyState::Consuming,
                                            std::memory_order_acquire,
                                            std::memory_order_relaxed)) {
        // Not an error. This is the consumer declining to wait, which is what
        // keeps storage latency off the critical path instead of in front of it.
        nAcquireMisses_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    work = &slot.work;
    nConsumes_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void ReadyRing::releaseConsumer(const ReadyWork* work) noexcept {
    const uint32_t idx = indexOf(work);
    if (idx == Capacity) {
        nBadHandles_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // Release: every read the consumer made of work.weights is complete before
    // the producer can claim this slot.
    slots_[idx].state.store(ReadyState::Empty, std::memory_order_release);
    consumer_.fetch_add(1, std::memory_order_relaxed);
    nReleases_.fetch_add(1, std::memory_order_relaxed);
}

ReadyRing::Counters ReadyRing::counters() const noexcept {
    Counters c;
    c.reserveAttempts = nReserveAttempts_.load(std::memory_order_relaxed);
    c.reserveFailures = nReserveFailures_.load(std::memory_order_relaxed);
    c.publishes = nPublishes_.load(std::memory_order_relaxed);
    c.publishRefusals = nPublishRefusals_.load(std::memory_order_relaxed);
    c.cancels = nCancels_.load(std::memory_order_relaxed);
    c.acquireAttempts = nAcquireAttempts_.load(std::memory_order_relaxed);
    c.acquireMisses = nAcquireMisses_.load(std::memory_order_relaxed);
    c.consumes = nConsumes_.load(std::memory_order_relaxed);
    c.releases = nReleases_.load(std::memory_order_relaxed);
    c.badHandleRejections = nBadHandles_.load(std::memory_order_relaxed);
    return c;
}

void ReadyRing::resetCounters() noexcept {
    nReserveAttempts_.store(0, std::memory_order_relaxed);
    nReserveFailures_.store(0, std::memory_order_relaxed);
    nPublishes_.store(0, std::memory_order_relaxed);
    nPublishRefusals_.store(0, std::memory_order_relaxed);
    nCancels_.store(0, std::memory_order_relaxed);
    nAcquireAttempts_.store(0, std::memory_order_relaxed);
    nAcquireMisses_.store(0, std::memory_order_relaxed);
    nConsumes_.store(0, std::memory_order_relaxed);
    nReleases_.store(0, std::memory_order_relaxed);
    nBadHandles_.store(0, std::memory_order_relaxed);
}

bool ReadyRing::idle() const noexcept {
    for (const Slot& slot : slots_) {
        if (slot.state.load(std::memory_order_acquire) != ReadyState::Empty) return false;
    }
    return true;
}

} // namespace Deep2
