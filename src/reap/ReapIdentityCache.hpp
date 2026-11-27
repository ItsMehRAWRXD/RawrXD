// ReapIdentityCache.hpp — RAWRXD production cache consumption of PR-06 identity.
// Bounded LRU cache keyed by CacheIdentity (weight key + selection fingerprint).
// Lookups never match across different selections/checkpoints/modes. Storage-
// independent; no RNG. Consumed by the engine residency/cache layer.
#pragma once
#include <cstdint>
#include <list>
#include <unordered_map>
#include <utility>

namespace RawrXD::Reap {

class IdentityCache {
public:
    explicit IdentityCache(uint64_t entryBudget) : budget_(entryBudget) {}
    // Returns true on a real identity hit (marks MRU). Never matches a different id.
    bool Lookup(uint64_t identity) {
        auto it = index_.find(identity);
        if (it == index_.end()) return false;
        lru_.splice(lru_.begin(), lru_, it->second);
        return true;
    }
    // Insert/refresh an identity; evicts LRU beyond budget.
    void Insert(uint64_t identity) {
        auto it = index_.find(identity);
        if (it != index_.end()) { lru_.splice(lru_.begin(), lru_, it->second); return; }
        if (budget_ == 0) return;
        while ((uint64_t)lru_.size() >= budget_ && !lru_.empty()) {
            index_.erase(lru_.back()); lru_.pop_back();
        }
        lru_.push_front(identity); index_[identity] = lru_.begin();
    }
    size_t Size() const noexcept { return index_.size(); }
private:
    std::list<uint64_t> lru_;
    std::unordered_map<uint64_t, std::list<uint64_t>::iterator> index_;
    uint64_t budget_;
};

} // namespace RawrXD::Reap