// ============================================================================
// TensorResidencyCache.hpp — RAWRXD_SPACELESS_UNMODEL_UNADDRESS_DESIGN_001
//
// Caches ExecutionView instances with LRU eviction. Each entry is a borrowed
// view — the cache does NOT own the bytes. It only tracks which identities are
// currently resident and provides an address lookup.
//
// Invariant: cache entries are invalidated when the underlying residency
// changes (generation bump on the LeaseToken). A stale view is never returned.
// ============================================================================
#pragma once

#include "ExecutionView.hpp"
#include "TensorIdentity.hpp"
#include <cstdint>
#include <cstddef>
#include <list>
#include <unordered_map>
#include <mutex>
#include <string>

namespace Deep2 {

struct TensorResidencyEntry {
    ExecutionView view;               // identity + transient address
    uint64_t      lastAccessEpoch = 0; // for LRU ordering
    uint64_t      pinCount        = 0; // >0 = do not evict
};

struct TensorResidencyCacheStats {
    uint64_t hits            = 0;
    uint64_t misses          = 0;
    uint64_t evictions       = 0;
    uint64_t insertions      = 0;
    uint64_t staleRejects    = 0; // returned a miss because lease generation changed
    uint64_t pinnedRejects   = 0; // eviction skipped because pinCount > 0
};

class TensorResidencyCache {
public:
    explicit TensorResidencyCache(size_t maxEntries = 256);
    ~TensorResidencyCache() = default;

    TensorResidencyCache(const TensorResidencyCache&) = delete;
    TensorResidencyCache& operator=(const TensorResidencyCache&) = delete;

    // Insert or refresh a view. If identity already present, updates address.
    void insert(const ExecutionView& view);

    // Look up by identity. Returns true + fills 'out' if resident and lease valid.
    bool lookup(const TensorIdentity& identity, ExecutionView& out);

    // Pin prevents eviction; unpin allows it again.
    void pin(const TensorIdentity& identity);
    void unpin(const TensorIdentity& identity);

    // Explicit eviction (e.g., called by ResidencyManager on budget pressure).
    // Returns true if evicted, false if not found or pinned.
    bool evict(const TensorIdentity& identity);

    // Evict least-recently-used until entry count <= maxEntries.
    // Skips pinned entries; returns number evicted.
    size_t evictLRU();

    // Invalidate all entries whose lease generation != currentGeneration.
    // Called after any residency transition.
    size_t invalidateStale(uint64_t currentGeneration);

    // Stats
    TensorResidencyCacheStats stats() const;
    size_t size() const;
    size_t capacity() const;

    // Diagnostic: dump current entries (for receipts / debugging)
    std::string dump() const;

private:
    mutable std::mutex mtx_;

    size_t maxEntries_;
    uint64_t epoch_ = 1;

    struct LRUNode {
        TensorIdentity identity;
        TensorResidencyEntry entry;
    };

    // LRU list: front = most recent, back = least recent
    std::list<LRUNode> lru_;

    // Map identity -> list iterator for O(1) touch
    struct IdentityHash {
        size_t operator()(const TensorIdentity& id) const noexcept {
            return id.hash();
        }
    };
    std::unordered_map<TensorIdentity, std::list<LRUNode>::iterator, IdentityHash> map_;

    TensorResidencyCacheStats stats_;

    void touch(std::list<LRUNode>::iterator it);
    size_t evictLRUInternal(); // assumes lock held
};

} // namespace Deep2
