// ============================================================================
// GPULayerOffloading.hpp - GPU Layer Offloading Engine
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct LayerOffloadConfig {
    uint32_t numLayers = 32;
    uint32_t gpuLayers = 0;
    uint64_t gpuMemoryBudget = 8ULL << 30;
    uint64_t cpuMemoryBudget = 16ULL << 30;
    bool enableAsyncTransfer = true;
    bool enablePipelinedOffload = true;
    uint32_t transferBatchSize = 4;
};

struct LayerAssignment {
    uint32_t layerIndex;
    bool onGPU;
    uint64_t weightSize;
    uint64_t gpuAddress;
    uint64_t cpuAddress;
    bool isTransferred;
    double transferTimeMs;
};

class GPULayerOffloading {
public:
    GPULayerOffloading();
    ~GPULayerOffloading();

    bool Initialize(const LayerOffloadConfig& config);
    void Shutdown();

    bool AssignLayers(const std::vector<uint64_t>& layerSizes);
    bool OffloadLayer(uint32_t layerIndex);
    bool PrefetchLayer(uint32_t layerIndex);
    bool EvictLayer(uint32_t layerIndex);

    bool EnsureLayerOnGPU(uint32_t layerIndex);
    bool EnsureLayerOnCPU(uint32_t layerIndex);

    uint32_t GetGPULayerCount() const;
    uint32_t GetCPULayerCount() const;
    uint64_t GetGPUMemoryUsed() const;
    uint64_t GetCPUMemoryUsed() const;

    struct OffloadStats {
        uint64_t totalTransfers;
        uint64_t totalBytesTransferred;
        uint64_t gpuCacheHits;
        uint64_t gpuCacheMisses;
        double avgTransferTimeMs;
        double totalTransferTimeMs;
    };
    OffloadStats GetStats() const { return stats_; }

private:
    LayerOffloadConfig config_;
    std::vector<LayerAssignment> assignments_;
    OffloadStats stats_;
    bool initialized_ = false;
    mutable std::mutex mutex_;
    
    std::vector<uint32_t> gpuLRU_;
    uint64_t gpuMemoryUsed_ = 0;
    
    void UpdateLRU(uint32_t layerIndex);
    uint32_t FindEvictionVictim() const;
};

} // namespace Sovereign
