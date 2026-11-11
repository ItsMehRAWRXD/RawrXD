#pragma once
// Hotpatch safeguard core: unique GhostText request IDs, routing epoch, cancel.
// Standalone — no Win32IDE link. PROMOTE=0 CERTIFIED=0.
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>

namespace rawrxd::hotpatch {

struct GhostSafeguardState {
    std::atomic<uint64_t> nextRequestId{1};
    std::atomic<uint64_t> routingEpoch{1};
    std::atomic<uint64_t> cancelGeneration{0};
    std::mutex outstandingMu;
    std::unordered_set<uint64_t> outstanding;
    std::string activeModel;
};

inline uint64_t AllocateGhostRequestId(GhostSafeguardState& s) {
    const uint64_t id = s.nextRequestId.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(s.outstandingMu);
    s.outstanding.insert(id);
    return id;
}

inline uint64_t BumpRoutingEpoch(GhostSafeguardState& s, const std::string& model) {
    s.activeModel = model;
    const uint64_t epoch = s.routingEpoch.fetch_add(1, std::memory_order_acq_rel) + 1;
    s.cancelGeneration.fetch_add(1, std::memory_order_acq_rel);
    std::lock_guard<std::mutex> lock(s.outstandingMu);
    s.outstanding.clear();
    return epoch;
}

inline uint64_t CancelOutstandingGhost(GhostSafeguardState& s) {
    const uint64_t gen = s.cancelGeneration.fetch_add(1, std::memory_order_acq_rel) + 1;
    std::lock_guard<std::mutex> lock(s.outstandingMu);
    s.outstanding.clear();
    return gen;
}

inline bool GhostResponseStillValid(GhostSafeguardState& s, uint64_t requestId,
                                    uint64_t epochAtIssue, uint64_t cancelAtIssue) {
    if (epochAtIssue != s.routingEpoch.load(std::memory_order_acquire)) return false;
    if (cancelAtIssue != s.cancelGeneration.load(std::memory_order_acquire)) return false;
    std::lock_guard<std::mutex> lock(s.outstandingMu);
    return s.outstanding.find(requestId) != s.outstanding.end();
}

inline void CompleteGhostRequest(GhostSafeguardState& s, uint64_t requestId) {
    std::lock_guard<std::mutex> lock(s.outstandingMu);
    s.outstanding.erase(requestId);
}

}  // namespace rawrxd::hotpatch
