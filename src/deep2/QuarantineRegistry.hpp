/* QuarantineRegistry.hpp — Deep2 owned submission-quarantine registry.
 *
 * Pure, dependency-free, CPU-testable registry for retained (non-reclaimable)
 * submissions. endSubmitWait() and the transfer helpers register retained
 * resources here instead of silently leaking them; a later confirmed-idle
 * boundary (successful device-idle) or terminal device-loss teardown reclaims
 * exactly the retained set — and no in-flight resource is freed before its
 * completion is confirmed.
 *
 * Addresses the audit's seven defects:
 *   1. Holds ACTUAL resource ownership via a native deleter callback, not just
 *      a resource-kind tag.
 *   2. Reclamation EXECUTES the deleter (native destruction), then erases.
 *   3. Retain() is noexcept but catches allocation failure (returns false),
 *      so an OOM never terminates the process.
 *   4. A std::mutex serializes all access (thread-safe ownership).
 *   5. Copy construction/assignment are deleted (no duplicated ownership).
 *   6. ReclaimGeneration() requires prior ConfirmIdle() evidence; late
 *      completion uses ReclaimTicket().
 *   7. Tests verify the deleter is actually invoked (destruction ordering).
 *
 * The deleter is a function pointer + opaque context so Retain() performs no
 * heap allocation on the containment path beyond the amortized vector growth
 * (which is caught, not thrown, on failure).
 */
#pragma once

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <vector>

namespace Deep2 {
namespace Submit {

enum class ResourceKind : int {
    Fence = 0,
    CommandBuffer = 1,
    QueryPool = 2,
    DescriptorSet = 3,
    StagingBuffer = 4,
    Arena = 5,
    KvCache = 6,
    WeightPin = 7,
    Scratch = 8,
};

// Native deleter: destroys one resource. `ctx` is an opaque pointer to the
// resource owner's handle (e.g. a struct holding VkFence/VkCommandBuffer).
using ResourceDeleter = void (*)(void* ctx);

class QuarantineRegistry {
public:
    // Retain one resource with its native deleter. Returns a monotonic ticket,
    // or 0 if capacity is exhausted / allocation failed (fail-closed: the
    // caller must treat 0 as "not quarantined" and handle the resource itself).
    uint64_t Retain(uint64_t deviceGeneration, uint64_t epoch,
                    ResourceKind kind, ResourceDeleter deleter,
                    void* ctx) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (entries_.size() >= kCapacity) return 0;
            const uint64_t id = nextTicket_++;
            entries_.push_back({id, deviceGeneration, epoch, kind, deleter, ctx});
            return id;
        } catch (...) {
            return 0;  // allocation failure -> fail closed, no terminate
        }
    }

    // Record completion evidence: a device generation has been confirmed idle
    // (successful device-idle) or terminally torn down. Without this,
    // ReclaimGeneration() refuses to reclaim.
    void ConfirmIdle(uint64_t deviceGeneration) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (std::find(confirmed_.begin(), confirmed_.end(), deviceGeneration)
            == confirmed_.end())
            confirmed_.push_back(deviceGeneration);
    }

    // Reclaim every retained resource for a generation that has been confirmed
    // idle. Executes each resource's native deleter (destruction) then erases.
    // Returns the number reclaimed; 0 if the generation was not confirmed.
    size_t ReclaimGeneration(uint64_t deviceGeneration) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto cit = std::find(confirmed_.begin(), confirmed_.end(),
                                   deviceGeneration);
        if (cit == confirmed_.end()) return 0;   // no completion evidence
        confirmed_.erase(cit);
        size_t n = 0;
        for (const auto& e : entries_) {
            if (e.deviceGeneration == deviceGeneration) {
                if (e.deleter) e.deleter(e.ctx);   // native destruction
                ++n;
            }
        }
        entries_.erase(
            std::remove_if(entries_.begin(), entries_.end(),
                [&](const Entry& e) {
                    return e.deviceGeneration == deviceGeneration;
                }),
            entries_.end());
        return n;
    }

    // Reclaim a single ticket (late completion notification). Executes its
    // deleter. Returns true if the ticket was still quarantined.
    bool ReclaimTicket(uint64_t ticket) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = std::find_if(entries_.begin(), entries_.end(),
            [&](const Entry& e) { return e.ticket == ticket; });
        if (it == entries_.end()) return false;
        if (it->deleter) it->deleter(it->ctx);   // native destruction
        entries_.erase(it);
        return true;
    }

    size_t Size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }
    bool Empty() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.empty();
    }
    uint64_t NextTicket() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return nextTicket_;
    }
    bool Contains(uint64_t ticket) const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::any_of(entries_.begin(), entries_.end(),
            [&](const Entry& e) { return e.ticket == ticket; });
    }
    size_t CountForGeneration(uint64_t deviceGeneration) const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t n = 0;
        for (const auto& e : entries_)
            if (e.deviceGeneration == deviceGeneration) ++n;
        return n;
    }

    // Non-copyable: a quarantine registry owns live resources and must not be
    // duplicated (which would double-free or split ownership).
    QuarantineRegistry() = default;
    QuarantineRegistry(const QuarantineRegistry&) = delete;
    QuarantineRegistry& operator=(const QuarantineRegistry&) = delete;

private:
    struct Entry {
        uint64_t        ticket;
        uint64_t        deviceGeneration;
        uint64_t        epoch;
        ResourceKind    kind;
        ResourceDeleter deleter;
        void*           ctx;
    };

    static constexpr size_t kCapacity = 4096;
    mutable std::mutex      mutex_;
    std::vector<Entry>      entries_;
    std::vector<uint64_t>   confirmed_;   // generations with completion evidence
    uint64_t                nextTicket_ = 1;
};

} // namespace Submit
} // namespace Deep2