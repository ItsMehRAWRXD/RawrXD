// ============================================================================
// TensorHop.hpp - Minimal DMA abstraction for MoE expert prefetching
// ============================================================================

#pragma once
#include <cstdint>
#include <vector>
#include <atomic>

namespace Deep2 {

// ============================================================================
// Tensor Hop - Single DMA transfer descriptor
// ============================================================================
struct TensorHop {
    uint64_t sourceAddr;      // Source physical address (disk/DRAM)
    uint64_t destAddr;        // Destination VRAM/DRAM address
    size_t   bytes;           // Transfer size
    uint32_t layerIdx;        // Which layer this expert belongs to
    uint32_t expertIdx;       // Which expert within layer
    uint32_t priority;        // Higher = load sooner
<<<<<<< HEAD
    uint32_t deviceId;        // Target device: 0=CPU, 1+=GPU index (dual GPU support)
=======
>>>>>>> 23355fea2b0ee1997bf565eb381234bb6364d743
    bool     isPinned;        // Don't evict if true
};

// ============================================================================
// DMA Scheduler - Minimal async prefetch
// ============================================================================
class DMAScheduler {
public:
    DMAScheduler();
    ~DMAScheduler();

    // Initialize with max concurrent transfers
    bool Initialize(size_t maxConcurrentTransfers);

    // Queue a tensor hop for async execution
    void QueueHop(const TensorHop& hop);

    // Execute pending hops (call from background thread)
    void ExecutePending();

    // Wait for all pending transfers
    void WaitAll();

    // Check if hop is complete
    bool IsComplete(uint32_t layerIdx, uint32_t expertIdx);

    // Cancel pending hops for a layer
    void CancelLayer(uint32_t layerIdx);

    // Get stats
    struct Stats {
        uint64_t hopsQueued;
        uint64_t hopsCompleted;
        uint64_t bytesTransferred;
        double   avgTransferTimeMs;
    };
    Stats GetStats() const;

private:
    std::vector<TensorHop> pendingQueue_;
    std::vector<TensorHop> activeQueue_;
    std::atomic<bool> running_;
    size_t maxConcurrent_;
    
    // Stats
    Stats stats_;
    
    // Internal
    void ExecuteHop(const TensorHop& hop);
};

// ============================================================================
// Expert Prefetch Planner - Predictive loading
// ============================================================================
class PrefetchPlanner {
public:
    // Given router output, plan which experts to prefetch
    static std::vector<TensorHop> PlanPrefetches(
        const uint32_t* expertIds,      // Selected experts for current layer
        uint32_t numExperts,
        uint32_t currentLayer,
        uint32_t totalLayers,
        uint64_t baseWeightAddr,         // Base address of weight file
        size_t expertSizeBytes           // Size of one expert's weights
    );

    // Predict next layer's likely experts based on pattern
    static std::vector<uint32_t> PredictNextLayer(
        const uint32_t* currentExperts,
        uint32_t numExperts,
        uint32_t patternHistory          // Bitmask of recent patterns
    );
};

} // namespace Deep2
