// ============================================================================
// CycloneScheduler.hpp
// Temporal prediction + deadline-driven prefetch orchestration
//
// Cyclone answers: "What will I need, and by when?"
// Elastic answers: "Where is it, and what transfers are required?"
//
// Architecture:
//   Deep2 Forward Pass → Cyclone.Predict() → Elastic.AcquireTensor(deadline)
//                        ↓
//                   braid CPU/GPU/I/O lanes
// ============================================================================

#ifndef CYCLONE_SCHEDULER_HPP
#define CYCLONE_SCHEDULER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <functional>
#include <queue>

namespace Deep2 {

// Forward declaration
class ElasticResidencyManager;
class ElasticResidentTensor;

// ============================================================================
// Cyclone Tensor Demand Request
// ============================================================================
struct TensorDemand {
    std::string tensorName;
    uint32_t layerIndex = ~0u;
    uint32_t expertIndex = ~0u;      // ~0u = dense layer

    // Temporal prediction
    uint64_t predictedSequenceNumber = 0;  // when Cyclone thinks it's needed
    uint64_t deadlineTicks = 0;            // hard deadline (compute distance)
    uint32_t priority = 128;                 // 0 = highest (urgent), 255 = lowest (speculative)

    // Confidence
    float predictionConfidence = 1.0f;       // 0.0–1.0, from router/history
    bool fromRouter = false;                 // true = MoE router confirmed

    // Size hint for scheduling
    size_t estimatedBytes = 0;
};

// ============================================================================
// Cyclone Braid Lane State
// ============================================================================
enum class BraidLane : uint8_t {
    Compute     = 0,   // GPU/CPU compute (current layer)
    Predict     = 1,   // Next-layer prediction + router eval
    Demand      = 2,   // Elastic.AcquireTensor calls
    Evict       = 3,   // Elastic.ReleaseTensor / eviction
    Prefetch    = 4,   // Speculative future-layer reads
    Dequant     = 5,   // CPU-side dequantization
    Upload      = 6,   // DMA RAM→VRAM
    Count       = 7
};

// ============================================================================
// Lane Telemetry
// ============================================================================
struct BraidLaneTelemetry {
    std::atomic<uint64_t> cyclesActive{0};
    std::atomic<uint64_t> cyclesStalled{0};
    std::atomic<uint64_t> tasksCompleted{0};
    std::atomic<uint64_t> tasksDropped{0};

    void Reset() {
        cyclesActive = 0;
        cyclesStalled = 0;
        tasksCompleted = 0;
        tasksDropped = 0;
    }

    double Utilization() const {
        uint64_t active = cyclesActive.load();
        uint64_t stalled = cyclesStalled.load();
        uint64_t total = active + stalled;
        return total > 0 ? (double)active / (double)total : 0.0;
    }
};

// ============================================================================
// Cyclone Prediction Engine
// ============================================================================
class CyclonePredictionEngine {
public:
    struct LayerPattern {
        uint32_t layerIndex = 0;
        uint32_t hitCount = 0;
        uint32_t missCount = 0;
        float avgLatencyUs = 0.0f;
    };

    struct ExpertPattern {
        uint32_t expertIndex = 0;
        uint32_t activationCount = 0;
        float frequency = 0.0f;
    };

    CyclonePredictionEngine() = default;
    ~CyclonePredictionEngine() = default;

    // Record actual execution for learning
    void RecordLayerExecution(uint32_t layerIndex, uint64_t latencyUs);
    void RecordExpertActivation(uint32_t layerIndex, uint32_t expertIndex);
    void RecordPrefetchOutcome(uint32_t layerIndex, bool hit);

    // Predict next demands
    std::vector<TensorDemand> PredictNextLayer(uint32_t currentLayer,
                                                  uint64_t currentSequence,
                                                  uint64_t deadlineTicks);

    // MoE: predict expert demands from router logits
    std::vector<TensorDemand> PredictExperts(uint32_t layerIndex,
                                              const float* routerLogits,
                                              uint32_t numExperts,
                                              uint64_t currentSequence,
                                              uint64_t deadlineTicks);

    // Confidence-based filtering
    float GetLayerConfidence(uint32_t layerIndex) const;
    float GetExpertConfidence(uint32_t expertIndex) const;

    void ResetPatterns();

private:
    mutable std::mutex mutex_;
    std::map<uint32_t, LayerPattern> layerPatterns_;
    std::map<uint32_t, std::vector<ExpertPattern>> expertPatterns_;
    std::atomic<uint64_t> totalSequences_{0};

    static constexpr uint32_t kMaxHistory = 1000;
};

// ============================================================================
// Cyclone Scheduler (the temporal brain)
// ============================================================================
class CycloneScheduler {
public:
    struct Config {
        // Lookahead
        uint32_t prefetchLookaheadLayers = 3;
        uint32_t prefetchLookaheadExperts = 8;

        // Deadlines
        uint64_t defaultDeadlineTicks = 1000;      // ~1ms at 1GHz
        uint64_t urgentDeadlineTicks = 100;         // immediate
        uint64_t speculativeDeadlineTicks = 10000;  // ~10ms

        // Braid
        uint32_t maxConcurrentPrefetches = 4;
        uint32_t maxConcurrentUploads = 2;

        // Thresholds
        float minPrefetchConfidence = 0.3f;         // don't prefetch below this
        float routerConfidenceThreshold = 0.7f;     // router is "confirmed" above this

        // MoE
        bool enableMoEPrefetch = true;
        uint32_t topKExpertsToPrefetch = 2;         // prefetch top-K from router

        // Telemetry
        bool enableTelemetry = true;
        uint32_t telemetrySampleIntervalMs = 100;
    };

    explicit CycloneScheduler(const Config& config);
    ~CycloneScheduler();

    CycloneScheduler(const CycloneScheduler&) = delete;
    CycloneScheduler& operator=(const CycloneScheduler&) = delete;

    // Lifecycle
    bool Initialize(ElasticResidencyManager* elastic);
    void Shutdown();

    // ------------------------------------------------------------------------
    // Deep2 Forward Pass Integration
    // ------------------------------------------------------------------------

    // Called at the start of each layer's forward pass.
    // Cyclone predicts what will be needed and issues Elastic acquires.
    void OnLayerStart(uint32_t layerIndex,
                      uint64_t sequenceNumber,
                      const float* routerLogits = nullptr,
                      uint32_t numExperts = 0);

    // Called when layer compute completes.
    // Cyclone records timing and retires completed demands.
    void OnLayerComplete(uint32_t layerIndex,
                         uint64_t sequenceNumber,
                         uint64_t computeLatencyUs);

    // Called when a tensor is actually used (for LRU/telemetry)
    void OnTensorUsed(const std::string& tensorName,
                      uint64_t sequenceNumber);

    // ------------------------------------------------------------------------
    // Explicit Demand API (for Deep2 engine)
    // ------------------------------------------------------------------------

    // Urgent: block until tensor is in VRAM
    bool AcquireTensorNow(const std::string& tensorName,
                          uint32_t layerIndex = ~0u,
                          uint32_t expertIndex = ~0u);

    // Prefetch: non-blocking, best-effort
    void PrefetchTensor(const std::string& tensorName,
                        uint32_t layerIndex,
                        uint32_t expertIndex,
                        uint64_t deadlineTicks,
                        float confidence);

    // Release: tell Elastic we're done with this tensor
    void ReleaseTensor(const std::string& tensorName);

    // ------------------------------------------------------------------------
    // Braid Control
    // ------------------------------------------------------------------------

    void EnableLane(BraidLane lane);
    void DisableLane(BraidLane lane);
    bool IsLaneEnabled(BraidLane lane) const;

    // ------------------------------------------------------------------------
    // Telemetry
    // ------------------------------------------------------------------------

    struct TelemetrySnapshot {
        uint64_t timestampUs = 0;
        uint32_t currentLayer = 0;
        uint64_t currentSequence = 0;

        // Demand stats
        uint64_t demandsIssued = 0;
        uint64_t demandsSatisfied = 0;
        uint64_t demandsMissed = 0;
        uint64_t demandsDropped = 0;

        // Prefetch stats
        uint64_t prefetchesIssued = 0;
        uint64_t prefetchHits = 0;
        uint64_t prefetchMisses = 0;
        double prefetchHitRate = 0.0;

        // Latency
        double avgDemandLatencyUs = 0.0;
        double p99DemandLatencyUs = 0.0;
        double maxDemandLatencyUs = 0.0;

        // Lane utilization
        std::array<double, static_cast<size_t>(BraidLane::Count)> laneUtilization{};

        // Prediction
        float avgPredictionConfidence = 0.0f;
        uint32_t routerActivationsPredicted = 0;
        uint32_t routerActivationsCorrect = 0;
    };

    TelemetrySnapshot GetTelemetry() const;
    void ResetTelemetry();

    // ------------------------------------------------------------------------
    // Internal (called by Elastic on transfer completion)
    // ------------------------------------------------------------------------
    void OnTransferComplete(const std::string& tensorName,
                            uint64_t completionSequence);
    void OnTransferFailed(const std::string& tensorName,
                            uint64_t sequenceNumber);

private:
    // ------------------------------------------------------------------------
    // Internal Scheduling
    // ------------------------------------------------------------------------
    void SchedulerLoop();
    void TelemetryLoop();

    void ProcessDemandQueue();
    void ProcessPrefetchQueue();
    void UpdateLaneStates();

    // Priority calculation
    uint32_t CalculatePriority(const TensorDemand& demand) const;
    bool ShouldDrop(const TensorDemand& demand) const;

    // ------------------------------------------------------------------------
    // Members
    // ------------------------------------------------------------------------
    Config config_;
    ElasticResidencyManager* elastic_ = nullptr;
    std::unique_ptr<CyclonePredictionEngine> predictor_;

    // Demand queues
    struct QueuedDemand {
        TensorDemand demand;
        uint64_t enqueueSequence;
        uint64_t enqueueTimeUs;
    };

    std::vector<QueuedDemand> urgentQueue_;       // sorted by deadline
    std::vector<QueuedDemand> prefetchQueue_;     // sorted by confidence
    mutable std::mutex queueMutex_;

    // Active tracking
    std::map<std::string, uint64_t> activeDemands_;  // tensorName → sequence
    mutable std::mutex activeMutex_;

    // Braid lanes
    std::array<std::atomic<bool>, static_cast<size_t>(BraidLane::Count)> laneEnabled_;
    std::array<BraidLaneTelemetry, static_cast<size_t>(BraidLane::Count)> laneTelemetry_;

    // Threads
    std::atomic<bool> running_{false};
    std::thread schedulerThread_;
    std::thread telemetryThread_;

    // Sequence tracking
    std::atomic<uint64_t> currentSequence_{0};
    std::atomic<uint32_t> currentLayer_{0};

    // Telemetry accumulation
    mutable std::mutex telemetryMutex_;
    struct AccumulatedTelemetry {
        std::atomic<uint64_t> demandsIssued{0};
        std::atomic<uint64_t> demandsSatisfied{0};
        std::atomic<uint64_t> demandsMissed{0};
        std::atomic<uint64_t> demandsDropped{0};
        std::atomic<uint64_t> prefetchesIssued{0};
        std::atomic<uint64_t> prefetchHits{0};
        std::atomic<uint64_t> prefetchMisses{0};
        std::atomic<uint64_t> totalDemandLatencyUs{0};
        std::atomic<uint64_t> maxDemandLatencyUs{0};
    };
    AccumulatedTelemetry accum_;
};

} // namespace Deep2

#endif // CYCLONE_SCHEDULER_HPP
