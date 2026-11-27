// ReapExpertResidency.hpp — RAWRXD S02 (Streaming residency foundation)
// Bounded expert residency with LRU eviction and a hard byte budget. Consumes
// demand-driven acquisitions (S01); never materializes the full expert bank.
// Storage-independent; reusable by Streaming paging. No RNG.
#pragma once
#include <cstdint>
#include <list>
#include <unordered_map>
#include <utility>

namespace RawrXD::Reap {

class ExpertResidency {
public:
    explicit ExpertResidency(uint64_t budgetBytes) : budget_(budgetBytes) {}
    // Admit an expert (key = layer<<32|expert). Evicts LRU until it fits.
    // Returns false if a single expert exceeds the budget (reject, fail-closed).
    bool Admit(uint32_t layer, uint32_t expert, uint64_t bytes) {
        const uint64_t key = ((uint64_t)layer << 32) | expert;
        auto it = index_.find(key);
        if (it != index_.end()) { Touch(it->second); return true; }
        if (bytes > budget_) return false;
        while (used_ + bytes > budget_ && !lru_.empty()) Evict();
        lru_.push_front({key, bytes}); index_[key] = lru_.begin(); used_ += bytes;
        return true;
    }
    uint64_t Used() const noexcept { return used_; }
    uint64_t Budget() const noexcept { return budget_; }
    size_t Count() const noexcept { return index_.size(); }
private:
    using E = std::pair<uint64_t,uint64_t>;
    std::list<E> lru_; std::unordered_map<uint64_t, std::list<E>::iterator> index_;
    uint64_t budget_, used_ = 0;
    void Touch(std::list<E>::iterator it) { lru_.splice(lru_.begin(), lru_, it); }
    void Evict() { auto k = lru_.back().first; used_ -= lru_.back().second; lru_.pop_back(); index_.erase(k); }
};

} // namespace RawrXD::Reap