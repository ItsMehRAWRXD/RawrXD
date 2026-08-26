// ============================================================================
// GhostCache.hpp
// Reverse-engineered Ghost Cache (ARC-style predictor)
// Tracks evicted tensors and predicts rebind candidates.
// Fixed-capacity, thread-safe, hash-based.
// ============================================================================

#ifndef GHOST_CACHE_HPP
#define GHOST_CACHE_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>

namespace Deep2 {

// ============================================================================
// Ghost Cache Entry
// ============================================================================
struct GhostEntry {
    std::string tensorName;
    uint32_t    layerIndex = ~0u;
    uint32_t    score = 0;          // 0-255 reuse probability
    uint64_t    tick = 0;           // eviction timestamp (monotonic)
    uint64_t    hitCount = 0;       // times reloaded after eviction
    uint64_t    evictCount = 1;     // times evicted (can be >1)
};

// ============================================================================
// Ghost Cache
// ============================================================================
class GhostCache {
public:
    explicit GhostCache(size_t capacity = 16384);
    ~GhostCache() = default;

    // Non-copyable
    GhostCache(const GhostCache&) = delete;
    GhostCache& operator=(const GhostCache&) = delete;

    // Record that a tensor was evicted from residency
    void RecordEvict(const std::string& name, uint32_t layerIndex);

    // Record that a tensor was acquired (reloaded) after eviction
    // Returns true if this was a ghost hit (tensor had been evicted before)
    bool RecordHit(const std::string& name, uint32_t layerIndex);

    // Get reuse score for a tensor (0 = unknown/cold, 255 = hot ghost)
    // Returns 0 if tensor not in ghost cache
    uint32_t GetReuseScore(const std::string& name) const;

    // Get detailed entry info (returns false if not found)
    bool GetEntry(const std::string& name, GhostEntry& out) const;

    // Periodic decay: reduce all scores by 1 (call every N tokens or seconds)
    void Decay();

    // Select the tensor with the lowest ghost score (best eviction candidate)
    // Returns empty string if cache is empty
    std::string SelectVictim() const;

    // Statistics
    struct Stats {
        uint64_t evictionsRecorded = 0;
        uint64_t hitsRecorded = 0;
        uint64_t decayCycles = 0;
        size_t   currentSize = 0;
    };
    Stats GetStats() const;

    void Reset();

private:
    size_t Hash(const std::string& name) const;

    mutable std::mutex mutex_;
    std::vector<GhostEntry> table_;
    size_t capacity_;
    std::atomic<uint64_t> clock_{0};
    std::atomic<uint64_t> evictionsRecorded_{0};
    std::atomic<uint64_t> hitsRecorded_{0};
    std::atomic<uint64_t> decayCycles_{0};
};

} // namespace Deep2

#endif // GHOST_CACHE_HPP
