// ============================================================================
// ModelSharding.hpp - Model Sharding Engine for >RAM Models
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

enum class ShardStrategy { ROUND_ROBIN, LAYER_WISE, TENSOR_PARALLEL, PIPELINE_PARALLEL };

struct ShardConfig {
    ShardStrategy strategy = ShardStrategy::LAYER_WISE;
    uint32_t numShards = 4;
    uint64_t shardSize = 1ULL << 30;
    std::vector<std::string> shardPaths;
    bool enableMemoryMapping = true;
    bool enableLazyLoading = true;
    bool enablePrefetch = true;
    uint32_t prefetchWindow = 2;
};

struct ShardInfo {
    uint32_t index;
    std::string path;
    uint64_t offset;
    uint64_t size;
    uint32_t numLayers;
    std::vector<uint32_t> layerIndices;
    bool isLoaded;
    bool isMapped;
    void* mappedPtr;
};

class ModelSharding {
public:
    ModelSharding();
    ~ModelSharding();

    bool Initialize(const ShardConfig& config);
    void Shutdown();

    bool ShardModel(const std::string& modelPath, const std::string& outputDir);
    bool LoadShard(uint32_t shardIndex);
    bool UnloadShard(uint32_t shardIndex);
    bool PrefetchShard(uint32_t shardIndex);

    ShardInfo GetShardInfo(uint32_t index) const;
    std::vector<ShardInfo> GetAllShards() const;
    uint32_t GetLoadedShardCount() const;

    void* GetLayerWeights(uint32_t layerIndex) const;
    uint64_t GetLayerOffset(uint32_t layerIndex) const;

    struct ShardingStats {
        uint64_t totalShards;
        uint64_t loadedShards;
        uint64_t totalBytes;
        uint64_t loadedBytes;
        uint64_t prefetchHits;
        uint64_t prefetchMisses;
    };
    ShardingStats GetStats() const { return stats_; }

private:
    ShardConfig config_;
    std::vector<ShardInfo> shards_;
    ShardingStats stats_;
    bool initialized_ = false;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
