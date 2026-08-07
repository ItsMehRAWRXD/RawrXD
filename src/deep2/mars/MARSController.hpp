// ============================================================================
// MARSController.hpp - Memory Allocation + Routing System
// Dynamic orchestration layer between GGUF tensors and dual GPU backend.
// ============================================================================

#pragma once

#include "VRAMLease.hpp"
#include "VRAMManager.hpp"
#include "TensorHotpatch.hpp"
#include "DualGPUBackend.hpp"
#include <vector>
#include <memory>
#include <functional>
#include <atomic>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Tensor Graph Node
// Represents a tensor in the inference graph with placement metadata.
// ============================================================================
struct TensorGraphNode {
    uint64_t    tensorId;
    std::string name;
    size_t      bytes;
    int         gpu = -1;          // Current placement
    float       priority = 1.0f;
    bool        isWeight = false;  // Model weights (usually pinned)
    bool        isKVCache = false; // KV cache (can spill)
    bool        isActivation = false;
    int         producerLayer = -1;
    std::vector<int> consumerLayers;
};

// ============================================================================
// Tensor Graph
// ============================================================================
class TensorGraph {
public:
    void AddNode(const TensorGraphNode& node);
    TensorGraphNode* GetNode(uint64_t tensorId);
    const TensorGraphNode* GetNode(uint64_t tensorId) const;
    size_t GetNodeCount() const;
    std::vector<TensorGraphNode*> GetNodesOnGPU(int gpu);
    std::vector<TensorGraphNode*> GetNodesByLayer(int layer);

private:
    std::vector<std::unique_ptr<TensorGraphNode>> nodes_;
    std::unordered_map<uint64_t, TensorGraphNode*> idMap_;
};

// ============================================================================
// MARS Controller
// The dynamic orchestration layer.
// ============================================================================
class MARSController {
public:
    MARSController();
    ~MARSController();

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Initialize(size_t gpu0Bytes, size_t gpu1Bytes);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // ------------------------------------------------------------------------
    // Component Access
    // ------------------------------------------------------------------------
    VRAMManager*     GetVRAMManager()     { return &vramManager_; }
    TensorHotpatch*  GetTensorHotpatch()  { return &tensorHotpatch_; }
    DualGPUBackend*  GetDualGPUBackend()  { return &dualGPUBackend_; }
    TensorGraph*     GetTensorGraph()     { return &tensorGraph_; }

    // ------------------------------------------------------------------------
    // Tensor Placement
    // ------------------------------------------------------------------------
    // Resolve where a tensor should live based on runtime state
    int ResolvePlacement(
        size_t bytes,
        float priority,
        bool preferLowLatency);

    // Place tensor and create lease
    VRAMLease* PlaceTensor(
        uint64_t tensorId,
        const std::string& name,
        size_t bytes,
        float priority = 1.0f,
        bool hotpatchable = true);

    // ------------------------------------------------------------------------
    // Rebalancing
    // ------------------------------------------------------------------------
    // Continuous rebalancing loop
    void Rebalance();

    // Rebalance specific graph
    void RebalanceGraph(TensorGraph& graph);

    // Triggered by VRAM pressure
    void OnVRAMPressure(int gpu);

    // Triggered by GPU idle
    void OnGPUIdle(int gpu);

    // ------------------------------------------------------------------------
    // Reverse Recovery
    // ------------------------------------------------------------------------
    // Handle tensor fault
    bool HandleTensorFault(uint64_t tensorId);

    // Handle GPU failure
    bool HandleGPUFailure(int gpu);

    // ------------------------------------------------------------------------
    // Inference Integration
    // ------------------------------------------------------------------------
    // Called before each layer: ensure tensors are on the right GPU
    bool PrepareLayer(int layerIndex, int targetGPU);

    // Called after each layer: update access patterns
    void RecordLayerComplete(int layerIndex);

    // ------------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------------
    DynamicParity GetCurrentParity() const;
    size_t GetTotalResidentVRAM() const;
    size_t GetTotalEvictedBytes() const;

    // ------------------------------------------------------------------------
    // Stats
    // ------------------------------------------------------------------------
    struct Stats {
        uint64_t rebalanceCount = 0;
        uint64_t pressureEvents = 0;
        uint64_t idleEvents = 0;
        uint64_t faultRecoveries = 0;
        uint64_t gpuFailovers = 0;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    bool initialized_ = false;

    VRAMManager     vramManager_;
    TensorHotpatch  tensorHotpatch_;
    DualGPUBackend  dualGPUBackend_;
    TensorGraph     tensorGraph_;

    Stats stats_;
    mutable std::mutex statsMutex_;

    // Internal
    int SelectBestGPU(size_t bytes, float priority, bool preferLowLatency) const;
};

} // namespace MARS
} // namespace Deep2
