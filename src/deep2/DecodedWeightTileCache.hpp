#pragma once
// Bounded, reusable decoded weight windows. Consumers retain a shared lease,
// so eviction never invalidates a buffer currently used by an inference kernel.
// Source revisions must call Invalidate(key) before replacing the backing tensor.
#include "NativeTensorResidencyCache.hpp"
#include <algorithm>
#include <cstddef>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {
class DecodedWeightTileCache {
public:
    struct Stats {
        size_t residentBytes = 0;
        size_t budgetBytes = 0;
        // Cached entries held by external leases; excludes evicted leases.
        size_t cachedLeasedBytes = 0;
        // Includes evicted tiles still pinned by external inference leases.
        size_t totalLiveDecodedBytes = 0;
        uint64_t hits = 0, misses = 0, evictions = 0;
    };
    explicit DecodedWeightTileCache(TensorResidencyCache& source, size_t budgetBytes)
        : source_(source), budget_(budgetBytes) {}
    // A lease is immutable; concurrent consumers can share a decoded tile.
    std::shared_ptr<const std::vector<float>> Acquire(
        const std::string& key, size_t first, size_t count) {
        if (key.empty() || count == 0 ||
            count > std::numeric_limits<size_t>::max() / sizeof(float) ||
            first > std::numeric_limits<size_t>::max() - count) return {};
        const size_t bytes = count * sizeof(float);
        std::lock_guard<std::mutex> lock(mu_);
        const Key lookup{key, first, count};
        auto found = entries_.find(lookup);
        if (found != entries_.end()) {
            ++hits_;
            lru_.splice(lru_.begin(), lru_, found->second.position);
            return found->second.values;
        }
        ++misses_;
        // Serialize same-tile misses; no duplicate decompression or staging.
        // Optional strict cap includes leases that survived cache eviction.
        // Reclaim unpinned entries before rejecting a new decoded tile.
        if (hardLiveBudget_ != std::numeric_limits<size_t>::max()) {
            PruneExpiredLeases();
            size_t liveBytes = LiveBytes();
            while ((bytes > hardLiveBudget_ ||
                    liveBytes > hardLiveBudget_ - bytes) && !lru_.empty()) {
                EvictOldest();
                PruneExpiredLeases();
                liveBytes = LiveBytes();
            }
            if (bytes > hardLiveBudget_ ||
                liveBytes > hardLiveBudget_ - bytes) {
                ++admissionRejections_;
                return {};
            }
        }
        auto values = std::make_shared<std::vector<float>>(count);
        if (!source_.ReadRange(key, first, count, values->data())) return {};
        PruneExpiredLeases();
        live_.push_back(LiveLease{values, bytes});
        if (bytes <= budget_) {
            while (resident_ > budget_ - bytes && !lru_.empty())
                EvictOldest();
            lru_.push_front(lookup);
            entries_.emplace(lookup, Entry{values, lru_.begin(), bytes});
            resident_ += bytes;
        }
        return values;
    }
    void Invalidate(const std::string& key) {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (it->first.tensor == key) {
                resident_ -= it->second.bytes;
                lru_.erase(it->second.position);
                it = entries_.erase(it);
                ++evictions_;
            } else ++it;
        }
    }
    void Clear() {
        std::lock_guard<std::mutex> lock(mu_);
        evictions_ += entries_.size();
        entries_.clear();
        lru_.clear();
        resident_ = 0;
    }
    // Strict live-memory admission limit; pinned tiles count even after
    // eviction. Default disabled to preserve existing callers' semantics.
    void SetHardLiveBudget(size_t bytes) {
        std::lock_guard<std::mutex> lock(mu_);
        hardLiveBudget_ = bytes;
    }
    void SetBudget(size_t bytes) {
        std::lock_guard<std::mutex> lock(mu_);
        budget_ = bytes;
        while (resident_ > budget_ && !lru_.empty()) EvictOldest();
    }
    Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mu_);
        size_t leased = 0;
        for (const auto& entry : entries_) {
            if (entry.second.values.use_count() > 1) {
                const size_t bytes = entry.second.bytes;
                leased = bytes > std::numeric_limits<size_t>::max() - leased
                    ? std::numeric_limits<size_t>::max() : leased + bytes;
            }
        }
        const size_t liveBytes = LiveBytes();
        return {resident_, budget_, leased, liveBytes, hardLiveBudget_, admissionRejections_, hits_, misses_, evictions_};
    }
private:
    size_t LiveBytes() const {
        size_t liveBytes = 0;
        for (const auto& tracked : live_) {
            if (!tracked.values.expired()) {
                liveBytes = tracked.bytes > std::numeric_limits<size_t>::max() - liveBytes
                    ? std::numeric_limits<size_t>::max() : liveBytes + tracked.bytes;
            }
        }
        return liveBytes;
    }
    struct Key {
        std::string tensor;
        size_t first, count;
        bool operator==(const Key& rhs) const {
            return tensor == rhs.tensor && first == rhs.first && count == rhs.count;
        }
    };
    struct Hash {
        size_t operator()(const Key& k) const {
            size_t h = std::hash<std::string>{}(k.tensor);
            h ^= std::hash<size_t>{}(k.first) + size_t(0x9e3779b9) + (h<<6) + (h>>2);
            h ^= std::hash<size_t>{}(k.count) + size_t(0x9e3779b9) + (h<<6) + (h>>2);
            return h;
        }
    };
    struct Entry {
        std::shared_ptr<const std::vector<float>> values;
        std::list<Key>::iterator position;
        size_t bytes;
    };
    void EvictOldest() {
        auto found = entries_.find(lru_.back());
        if (found != entries_.end()) {
            resident_ -= found->second.bytes;
            entries_.erase(found);
            ++evictions_;
        }
        lru_.pop_back();
    }
    struct LiveLease {
        std::weak_ptr<const std::vector<float>> values;
        size_t bytes;
    };
    void PruneExpiredLeases() {
        live_.erase(std::remove_if(live_.begin(), live_.end(),
            [](const LiveLease& lease) { return lease.values.expired(); }),
            live_.end());
    }
    std::vector<LiveLease> live_;
    TensorResidencyCache& source_;
    mutable std::mutex mu_;
    size_t budget_, resident_ = 0;
    size_t hardLiveBudget_ = std::numeric_limits<size_t>::max();
    uint64_t admissionRejections_ = 0;
    uint64_t hits_ = 0, misses_ = 0, evictions_ = 0;
    std::list<Key> lru_;
    std::unordered_map<Key, Entry, Hash> entries_;
};
} // namespace Deep2
