#ifndef RAWRXD_INT4_WEIGHT_CACHE_HPP
#define RAWRXD_INT4_WEIGHT_CACHE_HPP
// ============================================================================
// Int4WeightCache.hpp -- quantize-once, reuse-forever packed INT4 residency.
// ----------------------------------------------------------------------------
// The first INT4 matvec on a tensor quantizes its F32 weights to packed INT4
// (per-64-block F16 scales). Re-quantizing on every token would add CPU work,
// temporary allocations, and latency -- negating the GPU advantage. This cache
// quantizes ONCE per tensor, keeps the packed representation resident under a
// bounded byte budget with LRU eviction, and reuses it across all subsequent
// matvecs (tokens, requests). Model-scoped keys prevent cross-model reuse.
//
// The caller's F32 weights are only needed for the one-time quantization; after
// the packed INT4 is cached, the F32 buffer can be freed (AVWM's memory win).
//
// Header-only, C++17, no deps beyond LossyQuant.hpp.
// ============================================================================
#include "deep2/LossyQuant.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace rawrxd::avwm {

class Int4WeightCache {
public:
    struct Entry {
        std::shared_ptr<const lossy::QuantTensor> quant; // packed INT4 + F16 scales
        uint64_t last_used = 0;
        uint64_t packed_bytes = 0; // packed + scales size
    };

    // Return the cached INT4 representation for `name`, quantizing once on a
    // miss. `W` (F32 weights, rows*cols) is only read on the first (build) call.
    // Returns nullptr on quantization failure. Thread-safe.
    std::shared_ptr<const lossy::QuantTensor> getOrBuild(
        const std::string& name, const float* W, size_t rows, size_t cols) {
        if (name.empty() || !W || rows == 0 || cols == 0) return nullptr;
        // Fast path: cache hit.
        {
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = entries_.find(name);
            if (it != entries_.end()) {
                it->second.last_used = ++clock_;
                touchLocked(it->first);
                hits_++;
                return it->second.quant;
            }
        }
        // Build (miss): quantize outside the lock (expensive).
        misses_++;
        lossy::BlockCfg cfg; cfg.bits = lossy::QBits::Int4; cfg.block = 64;
        auto q = std::make_shared<lossy::QuantTensor>();
        if (!lossy::Quantize(W, rows * cols, cfg, *q)) return nullptr;
        const uint64_t packedBytes =
            static_cast<uint64_t>(q->packed.size() + q->scales.size() * sizeof(uint16_t));

        std::lock_guard<std::mutex> lk(mtx_);
        // Another thread may have inserted while we quantized; reuse it.
        auto it = entries_.find(name);
        if (it != entries_.end()) {
            it->second.last_used = ++clock_;
            touchLocked(it->first);
            hits_++;
            return it->second.quant;
        }
        // Evict to make room.
        evictToFitLocked(packedBytes);
        if (packedBytes > budget_) {
            // Budget smaller than one tensor: still build (caller needs it), but
            // do not retain -- return the shared_ptr and let the caller hold it.
            // (We do not insert; the caller's shared_ptr keeps it alive.)
            return q;
        }
        Entry e;
        e.quant = q;
        e.last_used = ++clock_;
        e.packed_bytes = packedBytes;
        auto [pos, inserted] = entries_.emplace(name, std::move(e));
        touchLocked(name);
        resident_ += packedBytes;
        return pos->second.quant;
    }

    void setBudget(size_t bytes) {
        std::lock_guard<std::mutex> lk(mtx_);
        budget_ = bytes;
        evictToFitLocked(0);
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mtx_);
        entries_.clear();
        lru_.clear();
        resident_ = 0;
    }

    struct Stats {
        size_t budget = 0;
        size_t resident = 0;
        size_t entries = 0;
        uint64_t hits = 0, misses = 0, evictions = 0;
    };
    Stats stats() const {
        std::lock_guard<std::mutex> lk(mtx_);
        Stats s;
        s.budget = budget_;
        s.resident = static_cast<size_t>(resident_);
        s.entries = entries_.size();
        s.hits = hits_;
        s.misses = misses_;
        s.evictions = evictions_;
        return s;
    }

private:
    void touchLocked(const std::string& name) {
        // Move to front (most-recently-used).
        for (auto it = lru_.begin(); it != lru_.end(); ++it) {
            if (*it == name) { lru_.erase(it); break; }
        }
        lru_.push_front(name);
    }

    void evictToFitLocked(uint64_t incomingBytes) {
        while (resident_ + incomingBytes > budget_ && !lru_.empty()) {
            const std::string victim = lru_.back();
            lru_.pop_back();
            auto it = entries_.find(victim);
            if (it == entries_.end()) continue;
            if (it->second.quant.use_count() > 1) {
                // A caller holds a shared_ptr -- cannot evict safely; skip.
                lru_.push_back(victim);
                // Avoid infinite loop: if all remaining are pinned, stop.
                bool allPinned = true;
                for (const auto& kv : entries_)
                    if (kv.second.quant.use_count() <= 1) { allPinned = false; break; }
                if (allPinned) break;
                continue;
            }
            resident_ -= it->second.packed_bytes;
            entries_.erase(it);
            evictions_++;
        }
    }

    std::unordered_map<std::string, Entry> entries_;
    std::list<std::string> lru_; // front = MRU
    size_t budget_ = 256ull * 1024 * 1024;
    uint64_t resident_ = 0, clock_ = 0;
    uint64_t hits_ = 0, misses_ = 0, evictions_ = 0;
    mutable std::mutex mtx_;
};

} // namespace rawrxd::avwm

#endif // RAWRXD_INT4_WEIGHT_CACHE_HPP