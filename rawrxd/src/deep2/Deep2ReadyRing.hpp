// ============================================================================
// Deep2ReadyRing.hpp
// RAWRXD_DEEP2_BOUNDED_STREAM_001
//
// Single-producer / single-consumer transport for resident expert weights.
//
// The ring is the boundary that removes storage capacity from the synchronous
// execution path. The consumer performs exactly one bounded operation per unit
// of work: acquire a slot, read a pointer and a length, release the slot. It
// performs no file I/O, no allocation, no model traversal, no residency
// decision, and no promotion. Everything of that kind happens on the producer
// side, before a slot reaches Ready.
//
// INVARIANTS
//   * Consumer never blocks. acquireConsumer() is a single CAS attempt and
//     returns false when nothing is ready. A false return is not an error; it
//     is back-pressure, and it is what makes the producer the only party that
//     can be late.
//   * A slot is published only after the producer has established that
//     work.weights is non-null and work.weightBytes is non-zero. The ring
//     refuses to publish otherwise, so a residency failure can never be
//     laundered into the bounded consumer as a null or zero-length pointer.
//   * cancelProducer() returns a slot to Empty WITHOUT advancing the producer
//     head. Advancing on cancel would skip a sequence number and permanently
//     desynchronize the producer and consumer cursors.
//   * Slot identity travels in the work record as slotIndex. Reconstructing a
//     Slot from a ReadyWork* would require offsetof on a type that contains a
//     std::atomic and is therefore not standard-layout, so that arithmetic is
//     only conditionally supported and is not used.
// ============================================================================

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace Deep2 {

enum class ReadyState : uint32_t {
    Empty = 0,
    Filling = 1,
    Ready = 2,
    Consuming = 3
};

// One unit of already-resident work handed from producer to consumer.
struct ReadyWork {
    uint64_t token = 0;
    uint32_t layer = 0;
    uint32_t expert = 0;

    // Resident, consumable bytes. Guaranteed non-null and non-zero once the
    // slot is published. The consumer is blind to where they were staged.
    const void* weights = nullptr;
    size_t weightBytes = 0;

    // Producer sequence number, and the cache-side lease that keeps the
    // allocation alive across eviction. The consumer releases the lease after
    // it has finished reading the bytes.
    uint64_t generation = 0;
    uint64_t leaseId = 0;

    // Slot identity. Set by reserveProducer; never written by the caller.
    uint32_t slotIndex = 0;
    uint32_t reserved = 0;
};

// Bounded SPSC ring. Capacity is fixed at construction; there is no growth and
// no heap allocation after the object exists, so the producer's working set
// never scales with model size.
class ReadyRing final {
public:
    static constexpr uint32_t Capacity = 64;

    ReadyRing() = default;
    ReadyRing(const ReadyRing&) = delete;
    ReadyRing& operator=(const ReadyRing&) = delete;

    // Producer side. reserveProducer claims a slot by moving Empty -> Filling.
    // The caller fills the returned record and then either publishes or
    // cancels. Returns false when the ring is full.
    bool reserveProducer(ReadyWork*& work) noexcept;

    // Promote Filling -> Ready. Refuses (and leaves the slot Filling for the
    // caller to cancel) if the payload is not consumable. On success the
    // producer head advances by one.
    bool publishProducer(ReadyWork* work) noexcept;

    // Producer side. Return Filling -> Empty without advancing either cursor.
    // Used when residency was not established.
    void cancelProducer(ReadyWork* work) noexcept;

    // Consumer side. Single non-blocking CAS attempt; no spin, no wait.
    bool acquireConsumer(const ReadyWork*& work) noexcept;

    // Consumer side. Return Consuming -> Empty and advance the consumer head.
    void releaseConsumer(const ReadyWork* work) noexcept;

    // Measurement. All counters are read-modify-write from two threads, so
    // they are relaxed rather than exact; the gate is an order-of-magnitude
    // assertion, not a benchmark.
    struct Counters {
        uint64_t reserveAttempts = 0;
        uint64_t reserveFailures = 0;   // ring full
        uint64_t publishes = 0;
        uint64_t publishRefusals = 0;  // null/zero payload rejected
        uint64_t cancels = 0;
        uint64_t acquireAttempts = 0;
        uint64_t acquireMisses = 0;    // nothing ready (back-pressure)
        uint64_t consumes = 0;
        uint64_t releases = 0;
        uint64_t badHandleRejections = 0;
    };

    Counters counters() const noexcept;
    void resetCounters() noexcept;

    // True when nothing is in Flight/Filling/Ready/Consuming.
    bool idle() const noexcept;

private:
    struct alignas(64) Slot {
        std::atomic<ReadyState> state{ReadyState::Empty};
        ReadyWork work{};
    };

    // Returns the slot index carried by `work`, or Capacity when the record is
    // not one this ring issued. A handle is rejected rather than trusted so a
    // corrupt or foreign pointer cannot index outside the array.
    uint32_t indexOf(const ReadyWork* work) const noexcept;

    Slot slots_[Capacity]{};

    alignas(64) std::atomic<uint64_t> producer_{0};
    alignas(64) std::atomic<uint64_t> consumer_{0};

    alignas(64) mutable std::atomic<uint64_t> nReserveAttempts_{0};
    std::atomic<uint64_t> nReserveFailures_{0};
    std::atomic<uint64_t> nPublishes_{0};
    std::atomic<uint64_t> nPublishRefusals_{0};
    std::atomic<uint64_t> nCancels_{0};
    std::atomic<uint64_t> nAcquireAttempts_{0};
    std::atomic<uint64_t> nAcquireMisses_{0};
    std::atomic<uint64_t> nConsumes_{0};
    std::atomic<uint64_t> nReleases_{0};
    std::atomic<uint64_t> nBadHandles_{0};
};

} // namespace Deep2
