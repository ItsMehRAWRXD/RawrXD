#include "FabricJukeboxBridge.h"
#include <Windows.h>
#include <iostream>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// FabricBlockProvider Implementation
// ============================================================================

FabricBlockProvider::FabricBlockProvider()
    : orchestrator_(nullptr)
    , optimizer_(nullptr)
    , initialized_(false) {
}

FabricBlockProvider::~FabricBlockProvider() {
    Shutdown();
}

bool FabricBlockProvider::Initialize(FabricOrchestrator* orchestrator,
                                     WANOptimizer* optimizer) {
    if (initialized_) {
        return false;
    }
    
    orchestrator_ = orchestrator;
    optimizer_ = optimizer;
    initialized_ = true;
    
    return true;
}

void FabricBlockProvider::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    // Clear cache
    {
        std::unique_lock<std::shared_mutex> lock(cacheMutex_);
        blockCache_.clear();
    }
    
    // Clear pending requests
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRequests_.clear();
    }
    
    initialized_ = false;
}

BlockRequestResult FabricBlockProvider::ResolveBlock(uint64_t blockId, 
                                                      uint32_t priority) {
    auto startTime = GetTimestampUs();
    BlockRequestResult result;
    result.blockId = blockId;
    result.location = BlockLocation::NOT_FOUND;
    result.data = nullptr;
    result.remoteNodeId = 0;
    result.latencyUs = 0;
    result.version = 0;
        auto it = blockCache_.find(blockId);
        if (it != blockCache_.end()) {
            result.location = BlockLocation::LOCAL_RAM;
            result.data = it->second;
            result.latencyUs = GetTimestampUs() - startTime;
            cacheHits_.fetch_add(1, std::memory_order_relaxed);
            totalResolutionLatencyUs_.fetch_add(result.latencyUs, std::memory_order_relaxed);
            resolutionCount_.fetch_add(1, std::memory_order_relaxed);
            return result;
        }
    }
    
    // 2. Check if orchestrator knows about this block
    if (orchestrator_) {
        // Convert blockId to tensorId (same namespace)
        void* localPtr = orchestrator_->ResolveTensor(blockId);
        if (localPtr) {
            result.location = BlockLocation::LOCAL_NUMA;
            result.data = localPtr;
            result.latencyUs = GetTimestampUs() - startTime;
            localHits_.fetch_add(1, std::memory_order_relaxed);
            totalResolutionLatencyUs_.fetch_add(result.latencyUs, std::memory_order_relaxed);
            resolutionCount_.fetch_add(1, std::memory_order_relaxed);
            return result;
        }
        
        // Check residency table for remote location
        ResidencyEntry entry;
        if (orchestrator_->GetResidencyTable()->Lookup(blockId, entry)) {
            if (entry.state == ResidencyState::RAM_HOT || 
                entry.state == ResidencyState::RAM_WARM) {
                if (entry.nodeId == 0) {
                    // Should be local but not found - inconsistency
                    result.location = BlockLocation::NOT_FOUND;
                } else {
                    // Remote block
                    result.location = BlockLocation::REMOTE_FABRIC;
                    result.remoteNodeId = entry.nodeId;
                    result.version = entry.version;
                    result.needsFetch = true;
                    remoteFetches_.fetch_add(1, std::memory_order_relaxed);
                }
                result.latencyUs = GetTimestampUs() - startTime;
                totalResolutionLatencyUs_.fetch_add(result.latencyUs, std::memory_order_relaxed);
                resolutionCount_.fetch_add(1, std::memory_order_relaxed);
                return result;
            }
        }
    }
    
    // 3. Not found anywhere
    result.location = BlockLocation::NOT_FOUND;
    result.latencyUs = GetTimestampUs() - startTime;
    cacheMisses_.fetch_add(1, std::memory_order_relaxed);
    totalResolutionLatencyUs_.fetch_add(result.latencyUs, std::memory_order_relaxed);
    resolutionCount_.fetch_add(1, std::memory_order_relaxed);
    return result;
}

bool FabricBlockProvider::RequestBlockAsync(uint64_t blockId, uint32_t priority,
                                             std::function<void(const BlockRequestResult&)> callback) {
    if (!initialized_) {
        return false;
    }
    
    // Check if immediately available
    auto result = ResolveBlock(blockId, priority);
    if (result.location != BlockLocation::REMOTE_FABRIC) {
        // Immediate callback
        callback(result);
        return true;
    }
    
    // Queue async fetch
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRequests_[blockId] = callback;
    }
    
    // Trigger remote fetch
    if (orchestrator_) {
        orchestrator_->PrefetchTensor(blockId, priority);
    }
    
    return true;
}

bool FabricBlockProvider::CacheBlock(uint64_t blockId, void* data, uint32_t size) {
    std::unique_lock<std::shared_mutex> lock(cacheMutex_);
    blockCache_[blockId] = data;
    return true;
}

bool FabricBlockProvider::EvictBlock(uint64_t blockId) {
    std::unique_lock<std::shared_mutex> lock(cacheMutex_);
    return blockCache_.erase(blockId) > 0;
}

bool FabricBlockProvider::IsBlockCached(uint64_t blockId) {
    std::shared_lock<std::shared_mutex> lock(cacheMutex_);
    return blockCache_.find(blockId) != blockCache_.end();
}

bool FabricBlockProvider::PrefetchBlocks(const std::vector<uint64_t>& blockIds, 
                                         uint32_t priority) {
    if (!orchestrator_) {
        return false;
    }
    
    for (uint64_t blockId : blockIds) {
        orchestrator_->PrefetchTensor(blockId, priority);
    }
    
    return true;
}

FabricBlockProvider::Stats FabricBlockProvider::GetStats() const {
    Stats stats;
    stats.localHits = localHits_.load(std::memory_order_relaxed);
    stats.remoteFetches = remoteFetches_.load(std::memory_order_relaxed);
    stats.cacheHits = cacheHits_.load(std::memory_order_relaxed);
    stats.cacheMisses = cacheMisses_.load(std::memory_order_relaxed);
    stats.prefetchHits = prefetchHits_.load(std::memory_order_relaxed);
    stats.prefetchMisses = prefetchMisses_.load(std::memory_order_relaxed);
    
    auto totalRes = totalResolutionLatencyUs_.load(std::memory_order_relaxed);
    auto resCount = resolutionCount_.load(std::memory_order_relaxed);
    stats.avgResolutionLatencyUs = resCount > 0 ? 
        static_cast<double>(totalRes) / resCount : 0.0;
    
    auto totalFetch = totalFetchLatencyUs_.load(std::memory_order_relaxed);
    auto fetchCount = fetchCount_.load(std::memory_order_relaxed);
    stats.avgFetchLatencyUs = fetchCount > 0 ? 
        static_cast<double>(totalFetch) / fetchCount : 0.0;
    
    return stats;
}

uint64_t FabricBlockProvider::GetTimestampUs() const {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000) / freq.QuadPart;
}

void* FabricBlockProvider::FetchRemoteBlock(uint64_t blockId, uint64_t nodeId, 
                                           uint32_t priority) {
    auto startTime = GetTimestampUs();
    
    // In production: this would use the fabric to fetch the block
    // For now, return nullptr (async completion)
    
    auto elapsed = GetTimestampUs() - startTime;
    totalFetchLatencyUs_.fetch_add(elapsed, std::memory_order_relaxed);
    fetchCount_.fetch_add(1, std::memory_order_relaxed);
    
    return nullptr;
}

// ============================================================================
// FabricJukeboxStreamer Implementation
// ============================================================================

FabricJukeboxStreamer::FabricJukeboxStreamer()
    : provider_(nullptr)
    , initialized_(false)
    , remoteStreamingEnabled_(true)
    , prefetchWindow_(8)
    , currentBlock_(0)
    , currentOffset_(0)
    , hLocalFile_(INVALID_HANDLE_VALUE) {
}

FabricJukeboxStreamer::~FabricJukeboxStreamer() {
    Close();
}

bool FabricJukeboxStreamer::Initialize(FabricBlockProvider* provider,
                                       const std::string& localNvmePath) {
    provider_ = provider;
    localNvmePath_ = localNvmePath;
    initialized_ = true;
    return true;
}

bool FabricJukeboxStreamer::Open(const char* path) {
    if (!initialized_) {
        return false;
    }
    
    // Try to open local file as fallback
    std::string fullPath = localNvmePath_ + "/" + path;
    hLocalFile_ = CreateFileA(
        fullPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED,
        nullptr
    );
    
    currentBlock_ = 0;
    currentOffset_ = 0;
    
    return true;  // Success even if local file not found (fabric may have it)
}

void FabricJukeboxStreamer::Close() {
    if (hLocalFile_ != INVALID_HANDLE_VALUE) {
        CloseHandle(hLocalFile_);
        hLocalFile_ = INVALID_HANDLE_VALUE;
    }
    
    currentBlock_ = 0;
    currentOffset_ = 0;
}

size_t FabricJukeboxStreamer::Read(void* buffer, size_t size) {
    if (!initialized_ || !buffer || size == 0) {
        return 0;
    }
    
    size_t totalRead = 0;
    uint8_t* outPtr = static_cast<uint8_t*>(buffer);
    
    while (totalRead < size) {
        // Resolve current block
        auto result = provider_->ResolveBlock(currentBlock_, 128);
        
        if (result.location == BlockLocation::NOT_FOUND) {
            // Try local file
            if (hLocalFile_ != INVALID_HANDLE_VALUE) {
                DWORD bytesRead = 0;
                OVERLAPPED ov = {};
                ov.Offset = static_cast<DWORD>(currentOffset_ & 0xFFFFFFFF);
                ov.OffsetHigh = static_cast<DWORD>(currentOffset_ >> 32);
                
                if (ReadFile(hLocalFile_, outPtr, 
                            static_cast<DWORD>(size - totalRead), 
                            &bytesRead, &ov)) {
                    totalRead += bytesRead;
                    currentOffset_ += bytesRead;
                }
            }
            break;
        }
        
        if (result.location == BlockLocation::REMOTE_FABRIC && result.needsFetch) {
            // Async fetch - for now, skip
            // In production: would wait or return partial
            break;
        }
        
        // Copy data
        if (result.data) {
            size_t toCopy = std::min(size - totalRead, static_cast<size_t>(4096));  // Block size
            memcpy(outPtr, result.data, toCopy);
            outPtr += toCopy;
            totalRead += toCopy;
            currentOffset_ += toCopy;
        }
        
        currentBlock_++;
        
        // Update prefetch window
        UpdatePrefetchQueue();
    }
    
    return totalRead;
}

bool FabricJukeboxStreamer::Seek(uint64_t offset) {
    currentOffset_ = offset;
    currentBlock_ = offset / 4096;  // Assuming 4KB blocks
    
    if (hLocalFile_ != INVALID_HANDLE_VALUE) {
        // Note: Actual seek happens on next read with OVERLAPPED
    }
    
    return true;
}

uint64_t FabricJukeboxStreamer::Tell() const {
    return currentOffset_;
}

bool FabricJukeboxStreamer::IsOpen() const {
    return initialized_;
}

void FabricJukeboxStreamer::SetPrefetchWindow(uint32_t blocksAhead) {
    prefetchWindow_ = blocksAhead;
}

void FabricJukeboxStreamer::EnableRemoteStreaming(bool enable) {
    remoteStreamingEnabled_ = enable;
}

bool FabricJukeboxStreamer::ReadBlock(uint64_t blockId, void* buffer) {
    auto result = provider_->ResolveBlock(blockId, 128);
    
    if (result.data) {
        memcpy(buffer, result.data, 4096);  // Block size
        return true;
    }
    
    return false;
}

void FabricJukeboxStreamer::UpdatePrefetchQueue() {
    if (!provider_ || !remoteStreamingEnabled_) {
        return;
    }
    
    // Build prefetch list
    std::vector<uint64_t> toPrefetch;
    for (uint32_t i = 1; i <= prefetchWindow_; i++) {
        toPrefetch.push_back(currentBlock_ + i);
    }
    
    // Submit prefetch requests
    provider_->PrefetchBlocks(toPrefetch, 64);  // Lower priority
}

} // namespace Fabric
} // namespace RawrXD
