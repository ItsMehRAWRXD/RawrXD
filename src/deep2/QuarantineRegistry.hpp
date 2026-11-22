/* QuarantineRegistry.hpp — Deep2 owned submission-quarantine registry.
 *
 * Pure, dependency-free, CPU-testable registry for retained (non-reclaimable)
 * submissions. endSubmitWait() and the transfer helpers register retained
 * resources here instead of silently leaking them; a later confirmed-idle
 * boundary (successful device-idle) or terminal device-loss teardown reclaims
 * exactly the retained set — and no in-flight resource is freed before its
 * completion is confirmed.
 *
 * Transitive ownership: every resource kind referenced by an unresolved
 * submission (fence, command buffer, query pool, descriptor set, staging,
 * arena, KV cache, weight pin, scratch) is tracked so a single Retain() call
 * protects the whole dependency graph, and ReclaimGeneration() releases it
 * only after the generation is confirmed idle/lost.
 */
#pragma once

#include <algorithm>
#include <cstdint>
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

struct QuarantineEntry {
    uint64_t     ticket = 0;
    uint64_t     deviceGeneration = 0;
    uint64_t     epoch = 0;
    ResourceKind kind = ResourceKind::Fence;
};

class QuarantineRegistry {
public:
    // Register one retained resource for a device generation/epoch. Returns a
    // monotonic ticket id usable for late-completion reclamation.
    uint64_t Retain(uint64_t deviceGeneration, uint64_t epoch,
                    ResourceKind kind) noexcept {
        const uint64_t id = nextTicket_++;
        entries_.push_back({id, deviceGeneration, epoch, kind});
        return id;
    }

    // Reclaim every retained resource for a device generation that has been
    // confirmed idle (successful device-idle) or terminally torn down. Returns
    // the number reclaimed.
    size_t ReclaimGeneration(uint64_t deviceGeneration) noexcept {
        size_t n = 0;
        entries_.erase(
            std::remove_if(entries_.begin(), entries_.end(),
                [&](const QuarantineEntry& e) {
                    if (e.deviceGeneration == deviceGeneration) { ++n; return true; }
                    return false;
                }),
            entries_.end());
        return n;
    }

    // Reclaim a single ticket (late completion notification). Returns true if
    // the ticket was still quarantined.
    bool ReclaimTicket(uint64_t ticket) noexcept {
        const auto it = std::find_if(entries_.begin(), entries_.end(),
            [&](const QuarantineEntry& e) { return e.ticket == ticket; });
        if (it == entries_.end()) return false;
        entries_.erase(it);
        return true;
    }

    // Reclaim all entries of a specific kind for a generation.
    size_t ReclaimKind(uint64_t deviceGeneration, ResourceKind kind) noexcept {
        size_t n = 0;
        entries_.erase(
            std::remove_if(entries_.begin(), entries_.end(),
                [&](const QuarantineEntry& e) {
                    if (e.deviceGeneration == deviceGeneration && e.kind == kind) {
                        ++n; return true;
                    }
                    return false;
                }),
            entries_.end());
        return n;
    }

    size_t Size() const noexcept { return entries_.size(); }
    bool Empty() const noexcept { return entries_.empty(); }
    uint64_t NextTicket() const noexcept { return nextTicket_; }
    bool Contains(uint64_t ticket) const noexcept {
        return std::any_of(entries_.begin(), entries_.end(),
            [&](const QuarantineEntry& e) { return e.ticket == ticket; });
    }

    // Count quarantined entries for a generation (diagnostic).
    size_t CountForGeneration(uint64_t deviceGeneration) const noexcept {
        size_t n = 0;
        for (const auto& e : entries_)
            if (e.deviceGeneration == deviceGeneration) ++n;
        return n;
    }

private:
    std::vector<QuarantineEntry> entries_;
    uint64_t nextTicket_ = 1;
};

} // namespace Submit
} // namespace Deep2