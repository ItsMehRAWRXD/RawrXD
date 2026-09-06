// ============================================================================
// NVMeStream.cpp - Implementation
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 2
// ============================================================================

#include "NVMeStream.h"
#include "TelemetrySinks.hpp"
#include <cstdio>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace Deep2 {

NVMeStream::NVMeStream()
    : residentBytes(0), cacheHits(0), cacheMisses(0),
      pageFaults(0), currentTick(0)
#ifdef _WIN32
    , hFile(INVALID_HANDLE_VALUE), hFileMapping(nullptr), fileBase(nullptr)
#else
    , fd(-1), fileBase(nullptr)
#endif
{}

NVMeStream::~NVMeStream() {
    shutdown();
}

bool NVMeStream::initialize(const NVMeStreamConfig& cfg) {
    config = cfg;
    
#ifdef _WIN32
    // Open the GGUF file
    hFile = CreateFileA(config.modelPath.c_str(), GENERIC_READ,
                        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                        nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[NVMeStream] ERROR: Failed to open %s (err=%lu)\n",
               config.modelPath.c_str(), GetLastError());
        return false;
    }
    
    // Get file size
    if (!GetFileSizeEx(hFile, &fileSize)) {
        printf("[NVMeStream] ERROR: GetFileSizeEx failed\n");
        CloseHandle(hFile);
        return false;
    }
    
    // Create file mapping
    hFileMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY,
                                       0, 0, nullptr);
    if (!hFileMapping) {
        printf("[NVMeStream] ERROR: CreateFileMapping failed (err=%lu)\n",
               GetLastError());
        CloseHandle(hFile);
        return false;
    }
    
    // Map view of entire file (OS handles paging)
    fileBase = (const uint8_t*)MapViewOfFile(hFileMapping, FILE_MAP_READ,
                                               0, 0, 0);
    if (!fileBase) {
        printf("[NVMeStream] ERROR: MapViewOfFile failed (err=%lu)\n",
               GetLastError());
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return false;
    }
    
    printf("[NVMeStream] Mapped %s (%.2f GB)\n",
           config.modelPath.c_str(),
           (double)fileSize.QuadPart / (1024.0 * 1024.0 * 1024.0));
    printf("[NVMeStream] Max resident: %.2f GB\n",
           (double)config.maxResidentBytes / (1024.0 * 1024.0 * 1024.0));
#else
    fd = open(config.modelPath.c_str(), O_RDONLY);
    if (fd < 0) return false;
    
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return false; }
    fileSize = st.st_size;
    
    fileBase = (const uint8_t*)mmap(nullptr, fileSize, PROT_READ,
                                    MAP_PRIVATE | MAP_POPULATE, fd, 0);
    if (fileBase == MAP_FAILED) { close(fd); return false; }
    
    printf("[NVMeStream] Mapped %s (%.2f GB)\n",
           config.modelPath.c_str(), (double)fileSize / (1e9));
#endif
    
    return true;
}

void NVMeStream::registerExpert(int layerId, int expertId,
                                 int64_t fileOffset, size_t sizeBytes) {
    int64_t key = makeKey(layerId, expertId);
    ExpertMeta meta;
    meta.fileOffset = fileOffset;
    meta.sizeBytes = sizeBytes;
    expertMeta_[key] = meta;
}

const uint8_t* NVMeStream::acquireExpert(int layerId, int expertId,
                                          size_t& sizeBytes) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    updateTick();
    
    int64_t key = makeKey(layerId, expertId);
    
    // Check residency cache
    auto it = residencyCache_.find(key);
    if (it != residencyCache_.end() && it->second.isResident) {
        // Cache hit
        cacheHits++;
        touchEntry(key);
        sizeBytes = it->second.sizeBytes;
        return it->second.mappedPtr;
    }
    
    // Cache miss - page in from disk
    cacheMisses++;
    
    auto metaIt = expertMeta_.find(key);
    if (metaIt == expertMeta_.end()) {
        printf("[NVMeStream] ERROR: Expert %d/%d not registered\n",
               layerId, expertId);
        return nullptr;
    }
    
    const ExpertMeta& meta = metaIt->second;
    
    // Check if we need to evict
    while (residentBytes + meta.sizeBytes > config.maxResidentBytes) {
        evictLRU(meta.sizeBytes);
    }
    
    // Create residency entry (pointer into mmap)
    ExpertResidencyEntry entry;
    entry.layerId = layerId;
    entry.expertId = expertId;
    entry.mappedPtr = fileBase + meta.fileOffset;
    entry.sizeBytes = meta.sizeBytes;
    entry.lastAccessTick = currentTick;
    entry.accessCount = 1;
    entry.isResident = true;
    
    residencyCache_[key] = entry;
    residentBytes += meta.sizeBytes;

    // Streamer op / mmap residency — logical (+prefetch), not physical ReadFile.
    {
        const IoTransferId xfer = NoteNvmeRequest(meta.sizeBytes, false);
        NoteNvmeConsumed(xfer, meta.sizeBytes);
    }
    
    // Touch pages to force them into RAM (if prefetch enabled)
    if (config.enablePageMonitoring) {
        size_t pages = (meta.sizeBytes + config.pageSize - 1) / config.pageSize;
        for (size_t p = 0; p < pages; ++p) {
            volatile char c = entry.mappedPtr[p * config.pageSize];
            (void)c;
        }
        pageFaults += pages;
    }
    
    sizeBytes = meta.sizeBytes;
    return entry.mappedPtr;
}

void NVMeStream::releaseExpert(int layerId, int expertId) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    int64_t key = makeKey(layerId, expertId);
    auto it = residencyCache_.find(key);
    if (it != residencyCache_.end()) {
        // Just decrement access count; actual eviction happens via LRU
        it->second.accessCount--;
    }
}

bool NVMeStream::prefetchExpert(int layerId, int expertId) {
    if (!config.enablePrefetch) return false;
    
    std::lock_guard<std::mutex> lock(cacheMutex_);
    int64_t key = makeKey(layerId, expertId);
    
    // Already resident?
    auto it = residencyCache_.find(key);
    if (it != residencyCache_.end() && it->second.isResident) {
        return true;
    }
    
    auto metaIt = expertMeta_.find(key);
    if (metaIt == expertMeta_.end()) return false;
    
    const ExpertMeta& meta = metaIt->second;
    
    // Evict if needed
    while (residentBytes + meta.sizeBytes > config.maxResidentBytes) {
        evictLRU(meta.sizeBytes);
    }
    
    // Prefetch: touch pages to bring into RAM
    const uint8_t* ptr = fileBase + meta.fileOffset;
    size_t pages = (meta.sizeBytes + config.pageSize - 1) / config.pageSize;
    for (size_t p = 0; p < pages; ++p) {
        volatile char c = ptr[p * config.pageSize];
        (void)c;
    }
    
    ExpertResidencyEntry entry;
    entry.layerId = layerId;
    entry.expertId = expertId;
    entry.mappedPtr = ptr;
    entry.sizeBytes = meta.sizeBytes;
    entry.lastAccessTick = currentTick;
    entry.accessCount = 0;
    entry.isResident = true;
    
    residencyCache_[key] = entry;
    residentBytes += meta.sizeBytes;

    {
        const IoTransferId xfer = NoteNvmeRequest(meta.sizeBytes, /*prefetch*/ true);
        NoteNvmeConsumed(xfer, meta.sizeBytes);
    }
    
    return true;
}

void NVMeStream::prefetchPredicted(const int* expertIds, const float* weights,
                                    int count) {
    if (!config.enablePrefetch) return;
    
    // Prefetch top experts by weight (highest weight first)
    std::vector<std::pair<float, int>> ranked;
    for (int i = 0; i < count; i++) {
        ranked.push_back({weights[i], expertIds[i]});
    }
    using PairType = std::pair<float, int>;
    std::sort(ranked.begin(), ranked.end(), [](const PairType& a, const PairType& b) {
        return a.first > b.first;
    });
    
    int prefetchCount = (int)config.prefetchDepth < count ? (int)config.prefetchDepth : count;
    for (int i = 0; i < prefetchCount; i++) {
        // Use current layer context for prefetch
        // Layer context is set by the caller before prefetch operations
        prefetchExpert(currentLayerId_, ranked[i].second);
    }
}

void NVMeStream::evictLRU(size_t bytesToFree) {
    // Find LRU entries and evict
    std::vector<std::pair<uint64_t, int64_t>> candidates;
    for (const auto& [key, entry] : residencyCache_) {
        if (entry.isResident) {
            candidates.push_back({entry.lastAccessTick, key});
        }
    }
    
    // Sort by access time (oldest first)
    std::sort(candidates.begin(), candidates.end());
    
    size_t freed = 0;
    for (auto& [tick, key] : candidates) {
        if (freed >= bytesToFree) break;
        
        auto it = residencyCache_.find(key);
        if (it != residencyCache_.end()) {
            freed += it->second.sizeBytes;
            residentBytes -= it->second.sizeBytes;
            it->second.isResident = false;
            residencyCache_.erase(it);
        }
    }
}

void NVMeStream::touchEntry(int64_t key) {
    auto it = residencyCache_.find(key);
    if (it != residencyCache_.end()) {
        it->second.lastAccessTick = currentTick;
        it->second.accessCount++;
    }
}

void NVMeStream::updateTick() {
    currentTick++;
}

float NVMeStream::getHitRate() const {
    size_t total = cacheHits + cacheMisses;
    if (total == 0) return 0.0f;
    return (float)cacheHits / (float)total;
}

void NVMeStream::shutdown() {
#ifdef _WIN32
    if (fileBase) {
        UnmapViewOfFile(fileBase);
        fileBase = nullptr;
    }
    if (hFileMapping) {
        CloseHandle(hFileMapping);
        hFileMapping = nullptr;
    }
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
#else
    if (fileBase) {
        munmap((void*)fileBase, fileSize);
        fileBase = nullptr;
    }
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
#endif
    
    residencyCache_.clear();
    expertMeta_.clear();
    residentBytes = 0;
}

} // namespace Deep2
