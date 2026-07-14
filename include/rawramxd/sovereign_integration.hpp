/**
 * RawRamXD Phase 8: Sovereign Integration Layer
 * 
 * Hooks predictive prefetcher into RawrXD_Gold.exe inference loop.
 * Intercepts tensor loads, trains predictor on real patterns, prefetches before demand.
 */

#pragma once

#include "rawramxd/tensor_predictor.hpp"
#include "rawramxd/gpu_fabric.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_set>

namespace RawRamXD {

// =============================================================================
// INTEGRATION CONFIGURATION
// =============================================================================

struct SovereignConfig {
    // Enable predictive prefetching
    bool enablePrefetch = true;
    
    // Prefetch threshold: only prefetch if confidence > threshold
    float prefetchConfidenceThreshold = 0.7f;
    
    // Maximum prefetches per token
    uint32_t maxPrefetchesPerToken = 4;
    
    // Prefetch look-ahead (tokens)
    uint32_t prefetchLookAhead = 2;
    
    // Enable pattern learning
    bool enableLearning = true;
    
    // Learning window size (accesses)
    uint32_t learningWindowSize = 100;
    
    // Bandwidth limit for prefetch (bytes/sec)
    uint64_t prefetchBandwidthLimit = 6ULL * 1024 * 1024 * 1024; // 6 GB/s
};

// =============================================================================
// TENSOR ACCESS HOOK
// =============================================================================

using TensorLoadCallback = std::function<void*(uint64_t tensorId, size_t size, ComputeTargetType preferredTier)>;
using TensorAccessCallback = std::function<void(uint64_t tensorId, uint64_t offset, size_t size)>;

// =============================================================================
// SOVEREIGN INTEGRATION LAYER
// =============================================================================

class SovereignIntegration {
public:
    static SovereignIntegration& Instance();
    
    // Initialize with configuration
    bool Initialize(const SovereignConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Hook registration - call from inference engine
    void RegisterTensorLoad(TensorLoadCallback callback);
    void RegisterTensorAccess(TensorAccessCallback callback);
    
    // Intercept tensor loads (call this instead of direct fabric access)
    void* LoadTensor(uint64_t tensorId, size_t size, ComputeTargetType preferredTier);
    
    // Record tensor access for pattern learning
    void RecordTensorAccess(uint64_t tensorId, uint64_t offset, size_t size);
    
    // Called at start/end of token generation
    void OnTokenStart(uint64_t tokenIndex);
    void OnTokenComplete(uint64_t tokenIndex, uint64_t durationUs);
    
    // Called at layer boundaries (for fine-grained prefetch)
    void OnLayerStart(uint32_t layerIndex);
    void OnLayerComplete(uint32_t layerIndex);
    
    // Get prefetch recommendations
    std::vector<uint64_t> GetPrefetchRecommendations(uint64_t maxBytes);
    
    // Execute prefetch
    bool ExecutePrefetch(uint64_t tensorId);
    
    // Statistics
    struct Stats {
        uint64_t tensorsLoaded;
        uint64_t tensorsPrefetched;
        uint64_t prefetchHits;      // Prefetched tensor was accessed
        uint64_t prefetchMisses;    // Prefetched tensor not accessed
        uint64_t tokensProcessed;
        float avgStallPerTokenUs;
        float stallReductionPercent;
    };
    Stats GetStats() const;
    
    // Access underlying components
    TensorPredictor* GetPredictor() { return predictor_.get(); }
    PrefetchOrchestrator* GetOrchestrator() { return orchestrator_.get(); }
    GPUFabric* GetFabric() { return &GPUFabric::Instance(); }
    
private:
    SovereignIntegration() = default;
    ~SovereignIntegration() = default;
    
    SovereignIntegration(const SovereignIntegration&) = delete;
    SovereignIntegration& operator=(const SovereignIntegration&) = delete;
    
    bool initialized_ = false;
    SovereignConfig config_;
    
    std::unique_ptr<TensorPredictor> predictor_;
    std::unique_ptr<PrefetchOrchestrator> orchestrator_;
    
    // Callbacks
    TensorLoadCallback loadCallback_;
    TensorAccessCallback accessCallback_;
    
    // Statistics
    Stats stats_{};
    mutable std::mutex statsMutex_;
    
    // Current state
    uint64_t currentToken_ = 0;
    uint32_t currentLayer_ = 0;
    
    // Prefetch tracking
    std::unordered_map<uint64_t, uint64_t> prefetchTimestamps_;
    std::unordered_set<uint64_t> activePrefetches_;
};

// =============================================================================
// C API FOR INTEGRATION
// =============================================================================

extern "C" {
    // Lifecycle
    __declspec(dllexport) bool RawRamXD_Sovereign_Init(const SovereignConfig* config);
    __declspec(dllexport) void RawRamXD_Sovereign_Shutdown();
    __declspec(dllexport) bool RawRamXD_Sovereign_IsReady();
    
    // Tensor operations
    __declspec(dllexport) void* RawRamXD_Sovereign_LoadTensor(
        uint64_t tensorId, size_t size, int preferredTier);
    __declspec(dllexport) void RawRamXD_Sovereign_RecordAccess(
        uint64_t tensorId, uint64_t offset, size_t size);
    
    // Token lifecycle
    __declspec(dllexport) void RawRamXD_Sovereign_TokenStart(uint64_t tokenIndex);
    __declspec(dllexport) void RawRamXD_Sovereign_TokenComplete(
        uint64_t tokenIndex, uint64_t durationUs);
    
    // Layer lifecycle
    __declspec(dllexport) void RawRamXD_Sovereign_LayerStart(uint32_t layerIndex);
    __declspec(dllexport) void RawRamXD_Sovereign_LayerComplete(uint32_t layerIndex);
    
    // Statistics
    __declspec(dllexport) void RawRamXD_Sovereign_GetStats(
        uint64_t* tensorsLoaded,
        uint64_t* tensorsPrefetched,
        uint64_t* prefetchHits,
        float* stallReductionPercent);
}

} // namespace RawRamXD
