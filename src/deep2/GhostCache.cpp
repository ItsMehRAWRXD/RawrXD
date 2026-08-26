// ============================================================================
// GhostCache.cpp
// Fixed-capacity hash table with linear probing.
// Thread-safe via coarse-grained mutex (intended for low-contention path).
// ============================================================================

#include "GhostCache.hpp"
#include <algorithm>

namespace Deep2 {

GhostCache::GhostCache(size_t capacity) : capacity_(capacity) {
    table_.resize(capacity);
    Reset();
}

void GhostCache::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& e : table_) {
        e.tensorName.clear();
        e.layerIndex = ~0u;
        e.score = 0;
        e.tick = 0;
        e.hitCount = 0;
        e.evictCount = 0;
    }
    clock_.store(0);
    evictionsRecorded_.store(0);
    hitsRecorded_.store(0);
    decayCycles_.store(0);
}

size_t GhostCache::Hash(const std::string& name) const {
    // FNV-1a 64-bit, folded to table size
    uint64_t hash = 14695981039346656037ULL;
    for (char c : name) {
        hash ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
        hash *= 1099511628211ULL;
    }
    return static_cast<size_t>(hash % capacity_);
}

void GhostCache::RecordEvict(const std::string& name, uint32_t layerIndex) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t idx = Hash(name);
    size_t start = idx;

    // Search for existing entry
    while (!table_[idx].tensorName.empty()) {
        if (table_[idx].tensorName == name) {
            // Already evicted before: increment evict count, boost score slightly
            table_[idx].evictCount++;
            table_[idx].score = static_cast<uint32_t>(
                std::min(255u, table_[idx].score + 1u));
            table_[idx].tick = clock_.fetch_add(1);
            evictionsRecorded_.fetch_add(1);
            return;
        }
        idx = (idx + 1) % capacity_;
        if (idx == start) break; // table full
    }

    // Insert new entry
    if (table_[idx].tensorName.empty()) {
        table_[idx].tensorName = name;
        table_[idx].layerIndex = layerIndex;
        table_[idx].score = 1;          // first eviction = low score
        table_[idx].tick = clock_.fetch_add(1);
        table_[idx].hitCount = 0;
        table_[idx].evictCount = 1;
        evictionsRecorded_.fetch_add(1);
        return;
    }

    // Table full: evict oldest (lowest tick) to make room
    size_t victimIdx = 0;
    uint64_t oldestTick = ~0ULL;
    for (size_t i = 0; i < capacity_; ++i) {
        if (table_[i].tick < oldestTick) {
            oldestTick = table_[i].tick;
            victimIdx = i;
        }
    }
    table_[victimIdx].tensorName = name;
    table_[victimIdx].layerIndex = layerIndex;
    table_[victimIdx].score = 1;
    table_[victimIdx].tick = clock_.fetch_add(1);
    table_[victimIdx].hitCount = 0;
    table_[victimIdx].evictCount = 1;
    evictionsRecorded_.fetch_add(1);
}

bool GhostCache::RecordHit(const std::string& name, uint32_t layerIndex) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t idx = Hash(name);
    size_t start = idx;

    while (!table_[idx].tensorName.empty()) {
        if (table_[idx].tensorName == name) {
            // Ghost hit: tensor was evicted and is now being reloaded
            table_[idx].hitCount++;
            table_[idx].score = static_cast<uint32_t>(
                std::min(255u, table_[idx].score + 6u)); // boost reuse score
            table_[idx].tick = clock_.fetch_add(1);
            hitsRecorded_.fetch_add(1);
            return true;
        }
        idx = (idx + 1) % capacity_;
        if (idx == start) break;
    }
    return false; // not a ghost hit (was never evicted)
}

uint32_t GhostCache::GetReuseScore(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t idx = Hash(name);
    size_t start = idx;

    while (!table_[idx].tensorName.empty()) {
        if (table_[idx].tensorName == name) {
            return table_[idx].score;
        }
        idx = (idx + 1) % capacity_;
        if (idx == start) break;
    }
    return 0;
}

bool GhostCache::GetEntry(const std::string& name, GhostEntry& out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t idx = Hash(name);
    size_t start = idx;

    while (!table_[idx].tensorName.empty()) {
        if (table_[idx].tensorName == name) {
            out = table_[idx];
            return true;
        }
        idx = (idx + 1) % capacity_;
        if (idx == start) break;
    }
    return false;
}

void GhostCache::Decay() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& e : table_) {
        if (!e.tensorName.empty() && e.score > 0) {
            e.score--;
        }
    }
    decayCycles_.fetch_add(1);
}

std::string GhostCache::SelectVictim() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t lowestScore = 256;
    size_t victimIdx = ~0ULL;

    for (size_t i = 0; i < capacity_; ++i) {
        if (!table_[i].tensorName.empty() && table_[i].score < lowestScore) {
            lowestScore = table_[i].score;
            victimIdx = i;
        }
    }

    if (victimIdx == ~0ULL) return "";
    return table_[victimIdx].tensorName;
}

GhostCache::Stats GhostCache::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats s;
    s.evictionsRecorded = evictionsRecorded_.load();
    s.hitsRecorded = hitsRecorded_.load();
    s.decayCycles = decayCycles_.load();
    s.currentSize = 0;
    for (const auto& e : table_) {
        if (!e.tensorName.empty()) s.currentSize++;
    }
    return s;
}

} // namespace Deep2
