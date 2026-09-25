#pragma once
// ============================================================================
// StreamRouter.h — Per-layer streaming router with prefetch / eviction
// ============================================================================
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace Deep2 {

class VramStreamingController;
class StreamEngine;
class ElasticResidencyManager;

struct StreamRouterConfig {
    uint32_t lookaheadLayers = 2;     // how many future layers to prefetch
    uint64_t prefetchBytesLimit = 0; // 0 = unlimited
    bool     enableEviction     = true;
};

struct StreamRouterPlan {
    std::vector<std::string> prefetch;
    std::vector<std::string> evict;
};

class StreamRouter {
public:
    StreamRouter();
    ~StreamRouter();

    StreamRouter(const StreamRouter&) = delete;
    StreamRouter& operator=(const StreamRouter&) = delete;

    void initialize(VramStreamingController* controller,
                    StreamEngine* engine,
                    ElasticResidencyManager* elasticMgr);

    // Called before processing a layer: returns plan of what to fetch / evict
    StreamRouterPlan planForLayer(uint32_t layer,
                                   const std::vector<std::string>& neededTensors);

    // Execute the plan (requests via StreamEngine, evicts via controller)
    bool executePlan(const StreamRouterPlan& plan);

    // After a layer completes: advance token, update LRU, optionally trigger evict
    void onLayerComplete(uint32_t layer, uint64_t tokenIndex);

    // Enable / disable lookahead prefetch
    void setLookaheadLayers(uint32_t n);
    uint32_t lookaheadLayers() const noexcept;

    void setConfig(const StreamRouterConfig& cfg);
    const StreamRouterConfig& config() const noexcept;

private:
    VramStreamingController* controller_ = nullptr;
    StreamEngine*            engine_     = nullptr;
    ElasticResidencyManager* elasticMgr_ = nullptr;
    StreamRouterConfig       cfg_;

    mutable std::mutex mtx_;
    std::unordered_map<uint32_t, std::vector<std::string>> layerTensorMap_;
};

} // namespace Deep2
