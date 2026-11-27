// ReapExpertResidency.hpp — RAWRXD S02 (Streaming residency foundation)
// Bounded expert residency with LRU eviction and a hard byte budget. Consumes
// demand-driven acquisitions (S01); never materializes the full expert bank.
// Storage-independent; reusable by Streaming paging. No RNG.
#pragma once
#include <cstdint>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace RawrXD::Reap {

class ExpertResidency {
public:
    explicit ExpertResidency(uint64_t budgetBytes) : budget_(budgetBytes) {}
    // Admit an expert (key = layer<<32|expert). Evicts LRU UNPINNED experts until it
    // fits. Returns false if a single expert exceeds the budget, or the budget is
    // full of pinned/in-flight experts (fail-closed; pinned are never evicted).
    bool Admit(uint32_t layer, uint32_t expert, uint64_t bytes) {
        const uint64_t key = ((uint64_t)layer << 32) | expert;
        auto it = index_.find(key);
        if (it != index_.end()) { Touch(it->second); return true; }
        if (bytes > budget_) return false;
        while (used_ + bytes > budget_) {
            if (!EvictOne()) return false;   // all remaining are pinned
        }
        lru_.push_front({key, bytes}); index_[key] = lru_.begin(); used_ += bytes;
        return true;
    }
    // Pin/unpin an expert so it cannot be evicted while in flight (ownership).
    void SetPinned(uint32_t layer, uint32_t expert, bool pinned) {
        const uint64_t key = ((uint64_t)layer << 32) | expert;
        if (pinned) pinned_.insert(key); else pinned_.erase(key);
    }
    // Fence completion: expert finished loading (kept resident; LRU touch).
    void Complete(uint32_t layer, uint32_t expert) {
        auto it = index_.find(((uint64_t)layer << 32) | expert);
        if (it != index_.end()) Touch(it->second);
    }
    bool Pinned(uint32_t layer, uint32_t expert) const {
        return pinned_.count(((uint64_t)layer << 32) | expert) != 0;
    }
    uint64_t Used() const noexcept { return used_; }
    uint64_t Budget() const noexcept { return budget_; }
    size_t Count() const noexcept { return index_.size(); }
private:
    using E = std::pair<uint64_t,uint64_t>;
    std::list<E> lru_; std::unordered_map<uint64_t, std::list<E>::iterator> index_;
    std::unordered_set<uint64_t> pinned_;
    uint64_t budget_, used_ = 0;
    void Touch(std::list<E>::iterator it) { lru_.splice(lru_.begin(), lru_, it); }
    // Evict the least-recently-used UNPINNED expert. Returns false if none evictable.
    bool EvictOne() {
        for (auto it = lru_.rbegin(); it != lru_.rend(); ++it) {
            if (pinned_.count(it->first)) continue;
            const uint64_t k = it->first;
            used_ -= it->second;
            lru_.erase(std::next(it).base());
            index_.erase(k);
            pinned_.erase(k);
            return true;
        }
        return false;
    }
};

} // namespace RawrXD::Reap