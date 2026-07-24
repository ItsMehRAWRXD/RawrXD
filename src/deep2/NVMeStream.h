// ============================================================================
// NVMeStream.h - NVMe Direct Streaming for Expert Weights
//
// VAL-000 Component: Memory Engine → NVMe Streaming
//
// Implements demand-paged expert weight loading directly from NVMe storage
// using Windows file APIs with memory mapping. Only the active expert slices
// are paged into RAM; cold experts remain on disk.
//
// Key features:
//   - Memory-mapped file I/O for zero-copy tensor access
//   - LRU eviction policy for expert residency
//   - Prefetch engine for predicted experts
//   - Page fault monitoring for cache optimization
//   - Direct NVMe submission queue bypass (optional)
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 2
// ============================================================================

#ifndef DEEP2_NVME_STREAM_H
#define DEEP2_NVME_STREAM_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>

#ifdef _WIN32
    #include <windows.h>
#endif

namespace Deep2 {

// ---------------------------------------------------------------------------
// Expert residency entry
// ---------------------------------------------------------------------------
struct ExpertResidencyEntry {
    int layerId;
    int expertId;
    const uint8_t* mappedPtr;     // Pointer into mmap region
    size_t sizeBytes;
    uint64_t lastAccessTick;      // For LRU
    uint64_t accessCount;
    bool isResident;
};

// ---------------------------------------------------------------------------
// NVMe streaming configuration
// ---------------------------------------------------------------------------
struct NVMeStreamConfig {
    std::string modelPath;          // Path to GGUF file
    size_t maxResidentBytes = 4ULL * 1024 * 1024 * 1024;  // 4 GB default
    size_t prefetchDepth = 2;       // Prefetch N experts ahead
    bool enablePrefetch = true;
    bool enablePageMonitoring = true;
    size_t pageSize = 4096;         // OS page size
};

// ---------------------------------------------------------------------------
// NVMeStream - Demand-paged expert weight streaming
// ---------------------------------------------------------------------------
class NVMeStream {
public:
    NVMeStream();
    ~NVMeStream();
    
    // Initialize with GGUF model path
    bool initialize(const NVMeStreamConfig& config);
    
    // Acquire expert weights (pages in if not resident)
    // Returns pointer to memory-mapped expert data
    const uint8_t* acquireExpert(int layerId, int expertId, size_t& sizeBytes);
    
    // Release expert (decrements refcount, eligible for eviction)
    void releaseExpert(int layerId, int expertId);
    
    // Prefetch expert (warm cache before use)
    bool prefetchExpert(int layerId, int expertId);
    
    // Predict and prefetch next experts based on router output
    void prefetchPredicted(const int* expertIds, const float* weights, int count);
    
    // Evict LRU entries to free memory
    void evictLRU(size_t bytesToFree);
    
    // Statistics
    size_t getResidentBytes() const { return residentBytes; }
    size_t getMaxResidentBytes() const { return config.maxResidentBytes; }
    size_t getCacheHits() const { return cacheHits; }
    size_t getCacheMisses() const { return cacheMisses; }
    float  getHitRate() const;
    size_t getPageFaults() const { return pageFaults; }
    
    // Register expert tensor metadata (called during model load)
    void registerExpert(int layerId, int expertId,
                         int64_t fileOffset, size_t sizeBytes);
    
    // Shutdown
    void shutdown();
    
private:
    NVMeStreamConfig config;
    
#ifdef _WIN32
    HANDLE hFile;
    HANDLE hFileMapping;
    const uint8_t* fileBase;        // Base of memory-mapped file
    LARGE_INTEGER fileSize;
#else
    int fd;
    const uint8_t* fileBase;
    size_t fileSize;
#endif
    
    // Expert metadata: layer+expert -> file offset + size
    struct ExpertMeta {
        int64_t fileOffset;
        size_t sizeBytes;
    };
    std::unordered_map<int64_t, ExpertMeta> expertMeta_;
    
    // Residency cache: layer+expert -> entry
    std::unordered_map<int64_t, ExpertResidencyEntry> residencyCache_;
    mutable std::mutex cacheMutex_;
    
    // Statistics
    size_t residentBytes;
    size_t cacheHits;
    size_t cacheMisses;
    size_t pageFaults;
    uint64_t currentTick;
    
    // Helpers
    int64_t makeKey(int layer, int expert) const {
        return ((int64_t)layer << 32) | (uint32_t)expert;
    }
    
    void touchEntry(int64_t key);
    void updateTick();
};

} // namespace Deep2

#endif // DEEP2_NVME_STREAM_H