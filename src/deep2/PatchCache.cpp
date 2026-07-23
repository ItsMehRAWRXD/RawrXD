// ============================================================================
// PatchCache.cpp - Cross-Bottle Intelligence Implementation
//
// Caches verified patches and enables reuse across bottles.
// Similarity matching allows finding "close enough" patches.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#include "PatchCache.hpp"
#include "HotPatcherSafety.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace Deep2 {

// ============================================================================
// CachedPatch Implementation
// ============================================================================

float CachedPatch::CalculateSimilarity(const CachedPatch& other) const {
    float similarity = 0.0f;
    
    // Pattern match (exact)
    if (threatPattern == other.threatPattern) {
        similarity += 0.3f;
    }
    
    // Region match (exact)
    if (targetRegion == other.targetRegion) {
        similarity += 0.2f;
    }
    
    // Code signature similarity (Jaccard index)
    if (!targetSignature.empty() && !other.targetSignature.empty()) {
        size_t matches = 0;
        size_t minLen = std::min(targetSignature.size(), other.targetSignature.size());
        for (size_t i = 0; i < minLen; i++) {
            if (targetSignature[i] == other.targetSignature[i]) {
                matches++;
            }
        }
        float sigSim = static_cast<float>(matches) / std::max(targetSignature.size(), other.targetSignature.size());
        similarity += sigSim * 0.5f;
    }
    
    return std::min(similarity, 1.0f);
}

float CachedPatch::CalculateSimilarity(const void* code, size_t len, const std::string& pattern) const {
    float similarity = 0.0f;
    
    // Pattern match
    if (threatPattern == pattern) {
        similarity += 0.4f;
    }
    
    // Code signature match
    if (!targetSignature.empty() && code != nullptr && len > 0) {
        auto codeHash = SHA256Checksum::compute(code, len);
        size_t matches = 0;
        size_t minLen = std::min(targetSignature.size(), codeHash.size());
        for (size_t i = 0; i < minLen; i++) {
            if (targetSignature[i] == codeHash[i]) {
                matches++;
            }
        }
        float sigSim = static_cast<float>(matches) / std::max(targetSignature.size(), codeHash.size());
        similarity += sigSim * 0.6f;
    }
    
    return std::min(similarity, 1.0f);
}

// ============================================================================
// PatchCache Implementation
// ============================================================================

class PatchCache::Impl {
public:
    std::unordered_map<std::string, CachedPatch> entries;
    std::unordered_map<std::string, std::vector<std::string>> patternIndex;
    PatchCacheConfig config;
    
    mutable std::mutex mutex;
    std::atomic<uint64_t> hits{0};
    std::atomic<uint64_t> misses{0};
    std::atomic<uint64_t> evictions{0};
    std::atomic<uint64_t> tokensSaved{0};
    
    bool initialized = false;
    
    bool Initialize(const PatchCacheConfig& cfg) {
        config = cfg;
        initialized = true;
        printf("[PatchCache] Initialized (max=%zu entries, TTL=%llums)\n",
               config.maxEntries, config.entryTTLMs);
        return true;
    }
    
    void Shutdown() {
        std::lock_guard<std::mutex> lock(mutex);
        entries.clear();
        patternIndex.clear();
        initialized = false;
        printf("[PatchCache] Shutdown\n");
    }
    
    std::string Store(const CachedPatch& patch) {
        std::lock_guard<std::mutex> lock(mutex);
        
        // Check if we need to evict
        if (entries.size() >= config.maxEntries) {
            EvictOldest();
        }
        
        // Generate cache ID
        std::string cacheId = "cache_" + patch.originalPatchId + "_" + 
                              std::to_string(patch.createdAt);
        
        CachedPatch entry = patch;
        entry.patchId = cacheId;
        entry.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        entry.lastUsedAt = entry.createdAt;
        entry.useCount = 0;
        
        entries[cacheId] = entry;
        patternIndex[entry.threatPattern].push_back(cacheId);
        
        printf("[PatchCache] Stored: %s (pattern=%s)\n", cacheId.c_str(), entry.threatPattern.c_str());
        return cacheId;
    }
    
    std::string FindSimilar(const void* targetCode, size_t codeLen, 
                           const std::string& threatPattern,
                           float* similarityOut) {
        std::lock_guard<std::mutex> lock(mutex);
        
        std::string bestMatch;
        float bestSimilarity = 0.0f;
        
        // Search in same pattern first
        auto it = patternIndex.find(threatPattern);
        if (it != patternIndex.end()) {
            for (const auto& patchId : it->second) {
                auto entryIt = entries.find(patchId);
                if (entryIt == entries.end()) continue;
                
                const auto& entry = entryIt->second;
                if (!entry.verified) continue;
                
                float sim = entry.CalculateSimilarity(targetCode, codeLen, threatPattern);
                if (sim > bestSimilarity && sim >= config.similarityThreshold) {
                    bestSimilarity = sim;
                    bestMatch = patchId;
                }
            }
        }
        
        // If no match in same pattern, search all
        if (bestMatch.empty()) {
            for (const auto& [patchId, entry] : entries) {
                if (!entry.verified) continue;
                
                float sim = entry.CalculateSimilarity(targetCode, codeLen, threatPattern);
                if (sim > bestSimilarity && sim >= config.similarityThreshold) {
                    bestSimilarity = sim;
                    bestMatch = patchId;
                }
            }
        }
        
        if (!bestMatch.empty()) {
            hits++;
            // Estimate tokens saved (rough heuristic)
            tokensSaved += 1000;  // ~1000 tokens per cache hit
            printf("[PatchCache] Hit: %s (similarity=%.2f)\n", bestMatch.c_str(), bestSimilarity);
        } else {
            misses++;
        }
        
        if (similarityOut) {
            *similarityOut = bestSimilarity;
        }
        
        return bestMatch;
    }
    
    bool Get(const std::string& patchId, CachedPatch& out) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = entries.find(patchId);
        if (it == entries.end()) return false;
        
        out = it->second;
        return true;
    }
    
    void MarkUsed(const std::string& patchId) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = entries.find(patchId);
        if (it != entries.end()) {
            it->second.useCount++;
            it->second.lastUsedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        }
    }
    
    void MarkVerified(const std::string& patchId, bool success) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = entries.find(patchId);
        if (it != entries.end()) {
            it->second.verified = true;
            it->second.verifiedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            
            if (success) {
                it->second.successCount++;
            } else {
                it->second.failureCount++;
            }
        }
    }
    
    bool Remove(const std::string& patchId) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = entries.find(patchId);
        if (it == entries.end()) return false;
        
        // Remove from pattern index
        auto& patternList = patternIndex[it->second.threatPattern];
        patternList.erase(std::remove(patternList.begin(), patternList.end(), patchId), patternList.end());
        
        entries.erase(it);
        return true;
    }
    
    void EvictOldest() {
        if (entries.empty()) return;
        
        // Find oldest entry
        std::string oldestId;
        uint64_t oldestTime = UINT64_MAX;
        
        for (const auto& [id, entry] : entries) {
            if (entry.lastUsedAt < oldestTime) {
                oldestTime = entry.lastUsedAt;
                oldestId = id;
            }
        }
        
        if (!oldestId.empty()) {
            Remove(oldestId);
            evictions++;
            printf("[PatchCache] Evicted: %s\n", oldestId.c_str());
        }
    }
    
    size_t ExpireOld(uint64_t maxAgeMs) {
        std::lock_guard<std::mutex> lock(mutex);
        
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        std::vector<std::string> toRemove;
        for (const auto& [id, entry] : entries) {
            if (now - entry.lastUsedAt > maxAgeMs) {
                toRemove.push_back(id);
            }
        }
        
        for (const auto& id : toRemove) {
            Remove(id);
        }
        
        printf("[PatchCache] Expired %zu old entries\n", toRemove.size());
        return toRemove.size();
    }
    
    void Clear() {
        std::lock_guard<std::mutex> lock(mutex);
        entries.clear();
        patternIndex.clear();
        printf("[PatchCache] Cleared all entries\n");
    }
    
    PatchCacheStats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex);
        
        PatchCacheStats stats;
        stats.totalEntries = entries.size();
        stats.totalBytes = 0;  // TODO: calculate
        stats.hits = hits.load();
        stats.misses = misses.load();
        stats.evictions = evictions.load();
        stats.tokensSaved = tokensSaved.load();
        
        uint64_t total = stats.hits + stats.misses;
        stats.hitRate = total > 0 ? static_cast<double>(stats.hits) / total : 0.0;
        
        return stats;
    }
};

// ============================================================================
// Public API Implementation
// ============================================================================

PatchCache::PatchCache() : impl_(std::make_unique<Impl>()) {}
PatchCache::~PatchCache() = default;

bool PatchCache::Initialize(const PatchCacheConfig& config) { return impl_->Initialize(config); }
void PatchCache::Shutdown() { impl_->Shutdown(); }

std::string PatchCache::Store(const CachedPatch& patch) { return impl_->Store(patch); }

std::string PatchCache::FindSimilar(const void* targetCode, size_t codeLen,
                                     const std::string& threatPattern,
                                     float* similarityOut) {
    return impl_->FindSimilar(targetCode, codeLen, threatPattern, similarityOut);
}

bool PatchCache::Get(const std::string& patchId, CachedPatch& out) { return impl_->Get(patchId, out); }
void PatchCache::MarkUsed(const std::string& patchId) { impl_->MarkUsed(patchId); }
void PatchCache::MarkVerified(const std::string& patchId, bool success) { impl_->MarkVerified(patchId, success); }
bool PatchCache::Remove(const std::string& patchId) { return impl_->Remove(patchId); }

void PatchCache::Clear() { impl_->Clear(); }
size_t PatchCache::ExpireOld(uint64_t maxAgeMs) { return impl_->ExpireOld(maxAgeMs); }

PatchCacheStats PatchCache::GetStats() const { return impl_->GetStats(); }

void PatchCache::PrintStatus() const {
    auto stats = GetStats();
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              PatchCache Status - Cross-Bottle Intelligence     ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Entries:          %4zu                                          ║\n", stats.totalEntries);
    printf("║ Hits:             %4llu                                          ║\n", stats.hits);
    printf("║ Misses:           %4llu                                          ║\n", stats.misses);
    printf("║ Hit Rate:         %6.2f%%                                        ║\n", stats.hitRate * 100);
    printf("║ Evictions:        %4llu                                          ║\n", stats.evictions);
    printf("║ Tokens Saved:      %4llu                                          ║\n", stats.tokensSaved);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}

// ============================================================================
// Global Instance
// ============================================================================

PatchCache& GetPatchCache() {
    static PatchCache instance;
    return instance;
}

// ============================================================================
// Convenience Functions
// ============================================================================

std::string TryCachedPatch(const void* targetCode,
                           size_t codeLen,
                           const std::string& threatPattern,
                           float* similarity) {
    return GetPatchCache().FindSimilar(targetCode, codeLen, threatPattern, similarity);
}

void CacheSuccessfulPatch(const std::string& patchId,
                            const void* targetCode,
                            size_t codeLen,
                            const std::string& threatPattern) {
    CachedPatch cacheEntry;
    cacheEntry.originalPatchId = patchId;
    cacheEntry.targetSignature.assign(
        SHA256Checksum::compute(targetCode, codeLen).begin(),
        SHA256Checksum::compute(targetCode, codeLen).end()
    );
    cacheEntry.threatPattern = threatPattern;
    cacheEntry.verified = true;
    cacheEntry.successCount = 1;
    
    GetPatchCache().Store(cacheEntry);
}

} // namespace Deep2
