//============================================================================
// nevm_prefetch.hpp
// RawrXD N-EVM Pre-fetch Engine
// Speculative tensor residency management
//============================================================================

#pragma once

#include "nevm_mmu.hpp"
#include "nevm_precision_controller.hpp"
#include <queue>
#include <future>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Pre-fetch Strategy
//============================================================================

enum class PrefetchStrategy {
    CONSERVATIVE = 0,   // Only prefetch on confirmed access patterns
    AGGRESSIVE = 1,     // Prefetch based on predicted next layers
    SPECULATIVE = 2,    // Prefetch based on precision controller hints
    ADAPTIVE = 3        // Dynamic strategy selection based on hit rate
};

//============================================================================
// Pre-fetch Request
//============================================================================

struct PrefetchRequest {
    VirtualTensorAddress vta;
    PrecisionMode target_format;
    ResidencyTarget target_residency;
    uint64_t priority;           // Higher = more urgent
    uint64_t deadline_tick;      // When this prefetch must complete
    bool blocking;               // If true, stall until complete
    
    // Callback for completion
    std::function<void(bool success)> on_complete;
};

//============================================================================
// Pre-fetch Engine
// Manages asynchronous tensor residency transitions
//============================================================================

class PrefetchEngine {
public:
    struct Config {
        size_t max_concurrent_prefetches;
        size_t prefetch_queue_depth;
        PrefetchStrategy strategy;
        float prefetch_threshold;    // Confidence threshold for speculative prefetch
        uint64_t prefetch_lookahead;   // How many layers ahead to prefetch
    };
    
    static Config DefaultConfig();
    
    PrefetchEngine(NeuralMMU* mmu, 
                   PrecisionController* controller,
                   const Config& config);
    ~PrefetchEngine();
    
    // Core prefetch operations
    // Returns: true if prefetch initiated (may complete async)
    //          false if prefetch failed immediately
    bool Prefetch(VirtualTensorAddress vta, 
                   PrecisionMode format,
                   bool blocking = false);
    
    // Batch prefetch for entire layer
    bool PrefetchLayer(uint8_t layer_id, 
                        PrecisionMode format,
                        uint64_t block_begin = 0,
                        uint64_t block_end = UINT64_MAX);
    
    // Speculative prefetch based on precision controller hints
    bool SpeculativePrefetch(VirtualTensorAddress vta,
                              float confidence);
    
    // Preemptive format upgrade (triggered by precision controller)
    bool UpgradeFormat(VirtualTensorAddress vta,
                        PrecisionMode new_format,
                        bool blocking = true);  // Default: block pipeline
    
    // Query prefetch status
    enum class PrefetchStatus {
        NOT_REQUESTED = 0,
        QUEUED = 1,
        IN_PROGRESS = 2,
        COMPLETED = 3,
        FAILED = 4,
        EVICTED = 5
    };
    PrefetchStatus GetStatus(VirtualTensorAddress vta) const;
    bool IsResident(VirtualTensorAddress vta) const;
    bool WaitFor(VirtualTensorAddress vta, uint64_t timeout_ms);
    
    // Pipeline integration
    // Called by execution engine before layer execution
    void OnLayerStart(uint8_t layer_id);
    void OnLayerComplete(uint8_t layer_id);
    void OnPrecisionChange(VirtualTensorAddress vta, PrecisionMode new_format);
    
    // Statistics
    struct Stats {
        uint64_t prefetches_requested;
        uint64_t prefetches_completed;
        uint64_t prefetches_failed;
        uint64_t prefetches_cancelled;
        uint64_t cache_hits;           // Prefetch not needed (already resident)
        uint64_t blocking_waits;       // Number of pipeline stalls
        uint64_t total_wait_ticks;     // Total stall time
        float hit_rate;                // Prefetch success rate
        float avg_prefetch_latency_ms;
    };
    Stats GetStats() const;
    void ResetStats();
    
private:
    NeuralMMU* mmu_;
    PrecisionController* controller_;
    Config config_;
    
    // Prefetch queue
    std::queue<PrefetchRequest> prefetch_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    // In-flight prefetches
    struct InFlightPrefetch {
        VirtualTensorAddress vta;
        std::future<bool> future;
        uint64_t start_tick;
        PrefetchRequest request;
    };
    std::vector<InFlightPrefetch> in_flight_;
    std::mutex in_flight_mutex_;
    
    // Status tracking
    std::unordered_map<uint64_t, PrefetchStatus> status_map_;
    mutable std::shared_mutex status_mutex_;
    
    // Worker thread
    std::atomic<bool> shutdown_;
    std::thread worker_thread_;
    
    // Statistics
    mutable Stats stats_;
    mutable std::mutex stats_mutex_;
    
    // Layer prediction
    uint8_t current_layer_;
    std::deque<uint8_t> layer_history_;
    std::mutex history_mutex_;
    
    // Private methods
    void WorkerLoop();
    bool ExecutePrefetch(const PrefetchRequest& request);
    void UpdateStatus(VirtualTensorAddress vta, PrefetchStatus status);
    void PredictNextLayers(std::vector<uint8_t>& out_layers);
    bool ShouldPrefetch(VirtualTensorAddress vta, float confidence);
    uint64_t GetTick() const;
};

//============================================================================
// Pipeline Stall Manager
// Minimizes stalls during format transitions
//============================================================================

class PipelineStallManager {
public:
    struct Config {
        uint64_t max_stall_ticks;        // Maximum allowed stall
        bool enable_double_buffering;    // Keep old+new format during transition
        bool enable_async_upgrade;       // Allow execution with old format while upgrading
    };
    
    PipelineStallManager(PrefetchEngine* prefetch, const Config& config);
    
    // Called when precision change requested
    // Returns: pointer to usable tensor (may be old format during transition)
    void* RequestPrecisionChange(VirtualTensorAddress vta,
                                    PrecisionMode new_format);
    
    // Non-blocking check
    bool IsReady(VirtualTensorAddress vta, PrecisionMode format);
    
    // Wait with timeout
    void* WaitForFormat(VirtualTensorAddress vta, 
                         PrecisionMode format,
                         uint64_t timeout_ms);
    
private:
    PrefetchEngine* prefetch_;
    Config config_;
    
    // Double buffer tracking
    struct DoubleBuffer {
        VirtualTensorAddress vta;
        PrecisionMode old_format;
        PrecisionMode new_format;
        void* old_ptr;
        void* new_ptr;
        bool transition_complete;
    };
    std::unordered_map<uint64_t, DoubleBuffer> double_buffers_;
    std::mutex buffer_mutex_;
};

//============================================================================
// Integration: Precision Controller + Pre-fetch
// Coordinated precision transitions
//============================================================================

class PrecisionPrefetchCoordinator {
public:
    PrecisionPrefetchCoordinator(PrecisionController* controller,
                                    PrefetchEngine* prefetch);
    
    // Called by precision controller when format change decided
    void OnPrecisionDecision(VirtualTensorAddress vta,
                             PrecisionMode old_format,
                             PrecisionMode new_format,
                             float urgency);
    
    // Called before tensor access
    // Returns: optimal format currently available
    PrecisionMode PrepareAccess(VirtualTensorAddress vta,
                                 PrecisionMode desired_format);
    
    // Called after tensor access (feedback)
    void RecordAccess(VirtualTensorAddress vta,
                       PrecisionMode format_used,
                       float compute_time_ms);
    
private:
    PrecisionController* controller_;
    PrefetchEngine* prefetch_;
    
    // Track pending upgrades
    std::unordered_map<uint64_t, PrecisionMode> pending_upgrades_;
    std::mutex upgrade_mutex_;
};

} // namespace NEVM
} // namespace RawrXD
