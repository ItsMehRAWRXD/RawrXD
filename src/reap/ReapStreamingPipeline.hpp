// ReapStreamingPipeline.hpp — RAWRXD S02-integration (Streaming end-to-end core)
// Ties demand-driven acquisition (S01) to bounded residency (S02): Acquire() is
// cache-aware — a residency hit returns the resident buffer; a miss acquires one
// expert from the source and admits it (LRU eviction under budget). Never
// materializes the full expert bank. Storage-independent; no RNG.
#pragma once
#include "reap/ReapExpertProvider.hpp"
#include "reap/ReapExpertResidency.hpp"
#include <cstdint>
#include <vector>

namespace RawrXD::Reap {

class StreamingPipeline {
public:
    StreamingPipeline(uint64_t budgetBytes, uint64_t expertBytes)
        : budget_(budgetBytes), expertBytes_(expertBytes), res_(budgetBytes) {}
    void Register(uint32_t layer, const SliceTensorDesc& t, const uint8_t* src) {
        provider_.Register(layer, t, src);
    }
    // Cache-aware acquire: returns pointer to a resident buffer (valid until the
    // next Acquire may evict). False on invalid/over-budget.
    bool Acquire(uint32_t layer, uint32_t expert, const uint8_t** out) {
        const uint64_t key = ((uint64_t)layer << 32) | expert;
        auto it = cache_.find(key);
        if (it != cache_.end()) { hits_++; *out = it->second.data(); return true; }
        if (expertBytes_ > budget_) return false;
        std::vector<uint8_t> buf(expertBytes_);
        if (!provider_.Acquire(layer, expert, buf.data(), buf.size())) return false;
        if (!res_.Admit(layer, expert, expertBytes_)) return false;   // may evict LRU
        cache_[key] = std::move(buf);
        *out = cache_[key].data(); ++misses_; return true;
    }
    uint64_t Hits() const noexcept { return hits_; }
    uint64_t Misses() const noexcept { return misses_; }
    uint64_t ResidencyUsed() const noexcept { return res_.Used(); }
private:
    uint64_t budget_, expertBytes_, hits_ = 0, misses_ = 0;
    ExpertProvider provider_;
    ExpertResidency res_;
    std::unordered_map<uint64_t, std::vector<uint8_t>> cache_;
};

} // namespace RawrXD::Reap