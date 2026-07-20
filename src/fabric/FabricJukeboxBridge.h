#pragma once

#include "../memory/jukebox.hpp"
#include "FabricOrchestrator.h"
#include "FabricTransport.h"
#include "TensorResidency.h"
#include "WANOptimizer.h"
#include <cstdint>
#include <functional>
#include <atomic>
#include <unordered_map>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// Fabric Jukebox Bridge - Universal Block Resolution
// 
// Integrates the Jukebox (VAL-030) with the Fabric (VAL-029) to create
// location-agnostic block streaming. The Jukebox no longer cares WHERE
// a block is - only that it gets the data.
// ============================================================================

// Block location types
enum class BlockLocation : uint32_t {
    LOCAL_NVME = 1,      // On local NVMe, use direct IO
    LOCAL_RAM = 2,       // In local RAM, direct access
    LOCAL_NUMA = 3,      // On local NUMA node, NUMA-aware access
    REMOTE_FABRIC = 4,   // On remote node, fetch via fabric
    PREFETCHING = 5,     // Async fetch in progress
    NOT_FOUND = 6        // Block doesn't exist
};

// Block request result
struct BlockRequestResult {
    uint64_t blockId;              // Requested block ID
    BlockLocation location;
    void* data;                    // Pointer to data (valid if location != REMOTE_FABRIC)
    uint64_t remoteNodeId;         // Valid if location == REMOTE_FABRIC
    uint64_t latencyUs;            // Resolution latency
    uint32_t version;              // Consistency version
    bool needsFetch;               // True if async fetch needed
};

// Fabric-aware block provider for Jukebox
class FabricBlockProvider {
public:
    FabricBlockProvider();
    ~FabricBlockProvider();
    
    // Initialization
    bool Initialize(FabricOrchestrator* orchestrator, 
                    WANOptimizer* optimizer = nullptr);
    void Shutdown();
    
    // Block resolution (synchronous)
    BlockRequestResult ResolveBlock(uint64_t blockId, uint32_t priority);
    
    // Async block fetch
    bool RequestBlockAsync(uint64_t blockId, uint32_t priority,
                          std::function<void(const BlockRequestResult&)> callback);
    
    // Block cache management
    bool CacheBlock(uint64_t blockId, void* data, uint32_t size);
    bool EvictBlock(uint64_t blockId);
    bool IsBlockCached(uint64_t blockId);
    
    // Prefetch hints
    bool PrefetchBlocks(const std::vector<uint64_t>& blockIds, uint32_t priority);
    
    // Statistics
    struct Stats {
        uint64_t localHits;
        uint64_t remoteFetches;
        uint64_t cacheHits;
        uint64_t cacheMisses;
        uint64_t prefetchHits;
        uint64_t prefetchMisses;
        double avgResolutionLatencyUs;
        double avgFetchLatencyUs;
    };
    Stats GetStats() const;
    
private:
    FabricOrchestrator* orchestrator_;
    WANOptimizer* optimizer_;
    bool initialized_;
    
    // Local block cache (blockId -> data)
    std::unordered_map<uint64_t, void*> blockCache_;
    mutable std::shared_mutex cacheMutex_;
    
    // Pending async requests
    std::unordered_map<uint64_t, std::function<void(const BlockRequestResult&)>> pendingRequests_;
    std::mutex pendingMutex_;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> localHits_{0};
    alignas(64) std::atomic<uint64_t> remoteFetches_{0};
    alignas(64) std::atomic<uint64_t> cacheHits_{0};
    alignas(64) std::atomic<uint64_t> cacheMisses_{0};
    alignas(64) std::atomic<uint64_t> prefetchHits_{0};
    alignas(64) std::atomic<uint64_t> prefetchMisses_{0};
    alignas(64) std::atomic<uint64_t> totalResolutionLatencyUs_{0};
    alignas(64) std::atomic<uint64_t> totalFetchLatencyUs_{0};
    alignas(64) std::atomic<uint64_t> resolutionCount_{0};
    alignas(64) std::atomic<uint64_t> fetchCount_{0};
    
    // Helpers
    uint64_t GetTimestampUs() const;
    void* FetchRemoteBlock(uint64_t blockId, uint64_t nodeId, uint32_t priority);
};

// ============================================================================
// Fabric-Aware Jukebox Streamer
// 
// Replaces the standard Jukebox Streamer with fabric-aware block resolution.
// The Jukebox now streams from the cluster, not just local NVMe.
// ============================================================================
class FabricJukeboxStreamer : public B008::Jukebox::IStreamer {
public:
    FabricJukeboxStreamer();
    ~FabricJukeboxStreamer() override;
    
    // Initialization
    bool Initialize(FabricBlockProvider* provider, 
                   const std::string& localNvmePath);
    
    // IStreamer interface
    bool Open(const char* path) override;
    void Close() override;
    size_t Read(void* buffer, size_t size) override;
    bool Seek(uint64_t offset) override;
    uint64_t Tell() const override;
    bool IsOpen() const override;
    
    // Fabric-specific
    void SetPrefetchWindow(uint32_t blocksAhead);
    void EnableRemoteStreaming(bool enable);
    
private:
    FabricBlockProvider* provider_;
    std::string localNvmePath_;
    bool initialized_;
    bool remoteStreamingEnabled_;
    uint32_t prefetchWindow_;
    
    // Current position
    uint64_t currentBlock_;
    uint64_t currentOffset_;
    
    // Prefetch queue
    std::vector<uint64_t> prefetchQueue_;
    
    // Local file handle (fallback)
    HANDLE hLocalFile_;
    
    // Helpers
    bool ReadBlock(uint64_t blockId, void* buffer);
    void UpdatePrefetchQueue();
};

} // namespace Fabric
} // namespace RawrXD
