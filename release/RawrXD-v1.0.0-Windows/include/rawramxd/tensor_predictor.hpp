/**
 * RawRamXD Phase 7C: Tensor Access Predictor
 * 
 * Predicts tensor hotness from telemetry patterns to enable prefetch-before-demand.
 * Transforms reactive migration into proactive residency management.
 */

#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <deque>
#include <memory>
#include <atomic>
#include <mutex>

namespace RawRamXD {

// Forward declarations
struct TensorResidency;
struct ComputeTarget;

// =============================================================================
// ACCESS PATTERN TYPES
// =============================================================================

enum class AccessPattern : uint32_t {
    UNKNOWN = 0,
    SEQUENTIAL = 1,      // Layer-by-layer, predictable
    STRIDED = 2,         // Attention heads, regular skips
    RANDOM = 3,          // KV cache lookup, unpredictable
    TEMPORAL = 4,        // Reused within time window
    ONCE = 5,            // Single access, never returns
};

struct AccessEvent {
    uint64_t timestampUs;
    uint64_t tensorHandle;
    uint32_t layerIndex;
    uint32_t opType;       // Operation that accessed tensor
    uint64_t computeTimeUs;
};

// =============================================================================
// PREDICTION CONFIDENCE
// =============================================================================

struct Prediction {
    uint64_t tensorHandle;
    float probability;       // 0.0 - 1.0 likelihood of access
    uint64_t predictedTimeUs;  // When access expected
    uint64_t prefetchDeadlineUs; // Must complete by this time
    AccessPattern pattern;
    float confidence;          // Model confidence
};

// =============================================================================
// TENSOR HOTNESS MODEL
// =============================================================================

struct TensorHotness {
    uint64_t tensorHandle;
    
    // Temporal metrics
    uint64_t lastAccessUs;
    uint64_t accessCount;
    uint64_t totalComputeTimeUs;
    
    // Predictive metrics
    float accessFrequency;     // Accesses per second
    float reuseProbability;    // Likelihood of reuse
    uint64_t expectedNextAccessUs;
    
    // Residency score (higher = more important to keep resident)
    float residencyScore;
    
    // Pattern detection
    AccessPattern detectedPattern;
    uint32_t patternConfidence;
};

// =============================================================================
// PREDICTIVE WINDOW
// =============================================================================

struct PrefetchWindow {
    uint64_t windowStartUs;
    uint64_t windowEndUs;
    uint64_t transferTimeUs;   // Time needed for migration
    uint64_t slackTimeUs;      // Buffer for safety
    
    bool CanHideTransfer(uint64_t transferCostUs) const {
        return transferCostUs < (windowEndUs - windowStartUs - slackTimeUs);
    }
};

// =============================================================================
// TENSOR ACCESS PREDICTOR
// =============================================================================

class TensorPredictor {
public:
    TensorPredictor();
    ~TensorPredictor();
    
    // Initialize with model characteristics
    bool Initialize(uint32_t layerCount, uint64_t tokenLatencyUs);
    void Shutdown();
    
    // Record access for pattern learning
    void RecordAccess(const AccessEvent& event);
    
    // Predict next accesses
    std::vector<Prediction> PredictNextAccesses(uint64_t horizonUs);
    
    // Get hotness for residency decisions
    TensorHotness GetHotness(uint64_t tensorHandle);
    std::vector<TensorHotness> GetHotTensors(uint32_t count);
    
    // Calculate prefetch window for upcoming compute
    PrefetchWindow CalculatePrefetchWindow(uint64_t currentTimeUs, 
                                           uint64_t nextComputeTimeUs);
    
    // Pattern detection
    AccessPattern DetectPattern(uint64_t tensorHandle);
    
    // Update model from actual outcomes (learning)
    void UpdatePredictionAccuracy(uint64_t tensorHandle, bool wasCorrect);
    
    // Statistics
    struct Stats {
        uint64_t totalPredictions;
        uint64_t correctPredictions;
        uint64_t falsePositives;
        uint64_t falseNegatives;
        float accuracy;
        float avgPredictionHorizonUs;
    };
    Stats GetStats() const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// =============================================================================
// PREFETCH ORCHESTRATOR
// =============================================================================

class PrefetchOrchestrator {
public:
    PrefetchOrchestrator(TensorPredictor* predictor);
    ~PrefetchOrchestrator();
    
    // Initialize with bandwidth constraints
    bool Initialize(uint64_t migrationBandwidthBytesPerSec);
    void Shutdown();
    
    // Main orchestration loop - call each token generation
    void OnTokenStart(uint64_t tokenIndex);
    void OnTokenComplete(uint64_t tokenIndex, uint64_t durationUs);
    
    // Get tensors that should be prefetched now
    std::vector<uint64_t> GetPrefetchCandidates(uint64_t maxBytes);
    
    // Get tensors that can be evicted (cold)
    std::vector<uint64_t> GetEvictionCandidates(uint64_t bytesNeeded);
    
    // Hide transfer during compute
    bool SchedulePrefetchDuringCompute(uint64_t tensorHandle, 
                                       uint64_t computeDurationUs);
    
    // Emergency prefetch (high latency tolerance)
    bool ScheduleEmergencyPrefetch(uint64_t tensorHandle);
    
    // Statistics
    struct Stats {
        uint64_t prefetchesIssued;
        uint64_t prefetchesCompleted;
        uint64_t prefetchesCancelled;
        uint64_t hiddenTransfers;      // Successfully overlapped
        uint64_t visibleStalls;        // Failed to hide
        float stallReductionPercent;   // vs reactive migration
    };
    Stats GetStats() const;
    
private:
    TensorPredictor* predictor_;
    uint64_t bandwidthBytesPerSec_;
    
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// =============================================================================
// C API
// =============================================================================

extern "C" {
    __declspec(dllexport) RawRamXD::TensorPredictor* RawRamXD_CreatePredictor();
    __declspec(dllexport) void RawRamXD_DestroyPredictor(RawRamXD::TensorPredictor* predictor);
    
    __declspec(dllexport) RawRamXD::PrefetchOrchestrator* RawRamXD_CreateOrchestrator(
        RawRamXD::TensorPredictor* predictor);
    __declspec(dllexport) void RawRamXD_DestroyOrchestrator(
        RawRamXD::PrefetchOrchestrator* orchestrator);
}

} // namespace RawRamXD
