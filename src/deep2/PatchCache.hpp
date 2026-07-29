// ============================================================================
// PatchCache.hpp - Cross-Bottle Intelligence System
//
// Caches verified patches and reuses them when similar situations arise.
// The system learns from each bottle opening, making subsequent openings
// faster and cheaper.
//
// Features:
//   - Similarity-based patch matching (address patterns, code signatures)
//   - Verified patch memoization
//   - Cross-bottle patch sharing
//   - Cache statistics and hit rates
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - Cross-Bottle Intelligence
// ============================================================================

#ifndef DEEP2_PATCH_CACHE_HPP
#define DEEP2_PATCH_CACHE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace Deep2 {

// ============================================================================
// Cached Patch Entry
// ============================================================================

struct CachedPatch {
    std::string patchId;           // Unique cache ID
    std::string originalPatchId;   // Source patch from first bottle
    
    // Patch content
    std::vector<uint8_t> patchBytes;
    size_t patchSize;
    void* targetAddress;           // Where it was applied
    
    // Context for similarity matching
    std::vector<uint8_t> targetSignature;  // Hash of original code
    std::string threatPattern;     // e.g., "xor", "anti-debug", "obfuscated"
    std::string targetRegion;      // e.g., "engine_core", "attention_kernel"
    
    // Verification status
    bool verified;                 // Has this patch been tested?
    uint64_t verifiedAt;           // When verified
    uint64_t successCount;         // How many times applied successfully
    uint64_t failureCount;         // How many times failed
    
    // Usage statistics
    uint64_t createdAt;
    uint64_t lastUsedAt;
    uint64_t useCount;
    
    // Similarity score (0-1) for matching
    float CalculateSimilarity(const CachedPatch& other) const;
    float CalculateSimilarity(const void* code, size_t len, const std::string& pattern) const;
};

// ============================================================================
// Patch Cache Configuration
// ============================================================================

struct PatchCacheConfig {
    size_t maxEntries = 1000;              // Maximum cached patches
    size_t maxBytes = 100 * 1024 * 1024;  // 100MB max cache
    float similarityThreshold = 0.85f;     // Minimum similarity for match
    uint64_t entryTTLMs = 3600000;         // 1 hour default TTL
    bool enableCrossBottleSharing = true;  // Share across bottles
    bool verifyBeforeReuse = true;        // Re-verify before applying cached patch
};

// ============================================================================
// Cache Statistics
// ============================================================================

struct PatchCacheStats {
    size_t totalEntries;
    size_t totalBytes;
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    double hitRate;
    uint64_t tokensSaved;  // Estimated tokens saved by cache hits
    
    // Per-pattern stats
    std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> patternHits; // pattern -> (hits, misses)
};

// ============================================================================
// Cross-Bottle Patch Cache
// ============================================================================

class PatchCache {
public:
    PatchCache();
    ~PatchCache();
    
    // Initialize cache
    bool Initialize(const PatchCacheConfig& config = PatchCacheConfig());
    void Shutdown();
    
    // =========================================================================
    // Cache Operations
    // =========================================================================
    
    // Store a verified patch in cache
    std::string Store(const CachedPatch& patch);
    
    // Find similar patch in cache
    // Returns patch ID if found, empty string if not
    std::string FindSimilar(const void* targetCode, 
                            size_t codeLen,
                            const std::string& threatPattern,
                            float* similarityOut = nullptr);
    
    // Get cached patch by ID
    bool Get(const std::string& patchId, CachedPatch& out);
    
    // Mark patch as used (updates statistics)
    void MarkUsed(const std::string& patchId);
    
    // Mark patch as verified
    void MarkVerified(const std::string& patchId, bool success);
    
    // Remove patch from cache
    bool Remove(const std::string& patchId);
    
    // =========================================================================
    // Cross-Bottle Sharing
    // =========================================================================
    
    // Export cache for sharing with other bottles
    std::vector<uint8_t> ExportCache(const std::string& patternFilter = "");
    
    // Import cache from another bottle
    size_t ImportCache(const std::vector<uint8_t>& data);
    
    // Merge caches (keeps highest-verified entries)
    void Merge(const PatchCache& other);
    
    // =========================================================================
    // Pattern-Based Operations
    // =========================================================================
    
    // Get all patches for a specific threat pattern
    std::vector<CachedPatch> GetByPattern(const std::string& pattern);
    
    // Get best patch for pattern (highest success rate)
    std::string GetBestForPattern(const std::string& pattern);
    
    // Preload patches for expected threats
    size_t PreloadPattern(const std::string& pattern);
    
    // =========================================================================
    // Cache Management
    // =========================================================================
    
    // Clear all entries
    void Clear();
    
    // Expire old entries
    size_t ExpireOld(uint64_t maxAgeMs);
    
    // Compact cache (remove low-quality entries)
    size_t Compact();
    
    // Get statistics
    PatchCacheStats GetStats() const;
    
    // Print status
    void PrintStatus() const;
    
    // =========================================================================
    // Smart Matching
    // =========================================================================
    
    // Find patch with fuzzy matching (handles slight variations)
    std::string FuzzyFind(const void* targetCode,
                          size_t codeLen,
                          float minSimilarity);
    
    // Learn from failure (adjusts similarity threshold)
    void LearnFromFailure(const std::string& attemptedPatchId,
                          const std::string& actualPatchId);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Global Cache Instance
// ============================================================================

PatchCache& GetPatchCache();

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick cache lookup with automatic application
std::string TryCachedPatch(const void* targetCode,
                           size_t codeLen,
                           const std::string& threatPattern,
                           float* similarity = nullptr);

// Store successful patch for future reuse
void CacheSuccessfulPatch(const std::string& patchId,
                            const void* targetCode,
                            size_t codeLen,
                            const std::string& threatPattern);

// ============================================================================
// Integration with HotPatcher
// ============================================================================
/*

USAGE:

// When opening a bottle:
void OpenBottle(void* threatLocation, const std::string& pattern) {
    // 1. Check cache first
    std::string cachedId = TryCachedPatch(threatLocation, 64, pattern);
    
    if (!cachedId.empty()) {
        // Cache hit! Apply cached patch
        printf("Cache hit! Using verified patch: %s\n", cachedId.c_str());
        GetHotPatcher().apply(cachedId);
        return;
    }
    
    // 2. Cache miss - generate new patch
    std::string newPatchId = GenerateAntidote(threatLocation, pattern);
    
    // 3. Apply and verify
    if (GetHotPatcher().apply(newPatchId)) {
        // 4. Store in cache for future bottles
        CacheSuccessfulPatch(newPatchId, threatLocation, 64, pattern);
    }
}

// Cross-bottle sharing:
void ShareBetweenBottles() {
    // Bottle A exports its learned patches
    auto cacheData = GetPatchCache().ExportCache("xor");
    
    // Bottle B imports them
    GetPatchCache().ImportCache(cacheData);
    
    // Now Bottle B knows all of Bottle A's verified XOR patches
}

*/

} // namespace Deep2

#endif // DEEP2_PATCH_CACHE_HPP
