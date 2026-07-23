// ============================================================================
// WarmupScheduler.hpp - Predictive Expert Prefetch Scheduler
//
// VAL-000 Component: Memory Engine → Warm-up Scheduler
//
// Predicts which experts will be needed based on routing history and
// prefetches their weights from NVMe before they're requested. This
// eliminates cache-miss latency during MoE execution.
//
// Strategy:
//   1. Track expert access patterns per layer
//   2. Build a Markov chain of expert transitions
//   3. Prefetch top-N most likely next experts
//   4. Warm the NVMe page cache via sequential reads
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 3
// ============================================================================

#ifndef DEEP2_WARMUP_SCHEDULER_HPP
#define DEEP2_WARMUP_SCHEDULER_HPP

#include <cstddef>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdio>
#include <algorithm>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Warmup configuration
// ---------------------------------------------------------------------------
struct WarmupConfig {
    size_t prefetchDepth = 3;        // Prefetch N experts ahead
    size_t historyWindow = 100;      // Track last N routing decisions
    size_t transitionMatrixSize = 256; // Max experts for Markov chain
    float  prefetchThreshold = 0.15f; // Min probability to prefetch
    bool   enableSequentialPrefetch = true; // Warm page cache
    size_t sequentialReadSize = 4096;  // Bytes to read for page warming
};

// ---------------------------------------------------------------------------
// Expert access record
// ---------------------------------------------------------------------------
struct ExpertAccess {
    int layerId;
    int expertId;
    uint64_t timestamp;
    float routingWeight;
};

// ---------------------------------------------------------------------------
// Expert transition probability
// ---------------------------------------------------------------------------
struct ExpertTransition {
    int   fromExpert;
    int   toExpert;
    float probability;
    uint64_t count;
};

// ---------------------------------------------------------------------------
// Prefetch request (local definition)
// ---------------------------------------------------------------------------
struct WarmupPrefetchRequest {
    int layerId;
    int expertId;
    float probability;
    int priority;  // Higher = more urgent
};

// ---------------------------------------------------------------------------
// Warmup statistics
// ---------------------------------------------------------------------------
struct WarmupStats {
    uint64_t totalPredictions = 0;
    uint64_t correctPredictions = 0;
    uint64_t prefetchesIssued = 0;
    uint64_t prefetchesHit = 0;     // Expert was used after prefetch
    uint64_t prefetchesWasted = 0;  // Expert was prefetched but not used
    double  predictionAccuracy = 0.0;
    double  prefetchHitRate = 0.0;
    double  avgPrefetchLatencyMs = 0.0;

    void updatePrediction(bool correct) {
        totalPredictions++;
        if (correct) correctPredictions++;
        predictionAccuracy = (double)correctPredictions / totalPredictions;
    }

    void updatePrefetch(bool hit) {
        prefetchesIssued++;
        if (hit) prefetchesHit++;
        else prefetchesWasted++;
        prefetchHitRate = (double)prefetchesHit / prefetchesIssued;
    }
};

// ---------------------------------------------------------------------------
// WarmupScheduler - Predictive expert prefetch
// ---------------------------------------------------------------------------
class WarmupScheduler {
public:
    WarmupScheduler();
    ~WarmupScheduler();

    // Initialize
    bool initialize(const WarmupConfig& config);

    // Record an expert access (called after routing)
    void recordAccess(int layerId, int expertId, float routingWeight);

    // Predict next experts for a given layer
    // Returns sorted list of (expertId, probability) pairs
    std::vector<WarmupPrefetchRequest> predictNextExperts(int layerId, int currentExpert = -1);

    // Get prefetch requests for all layers
    std::vector<WarmupPrefetchRequest> getPrefetchRequests();

    // Mark a prefetch as hit (expert was used)
    void markPrefetchHit(int layerId, int expertId);

    // Mark a prefetch as wasted (expert was not used)
    void markPrefetchWasted(int layerId, int expertId);

    // Warm the OS page cache by reading expert data sequentially
    void warmPageCache(const uint8_t* expertData, size_t sizeBytes);

    // Get statistics
    const WarmupStats& getStats() const { return stats_; }

    // Reset history (e.g., for new conversation)
    void reset();

    // Update config at runtime
    void setConfig(const WarmupConfig& config) { config_ = config; }
    const WarmupConfig& getConfig() const { return config_; }

private:
    WarmupConfig config_;
    WarmupStats stats_;
    std::mutex mutex_;

    // Per-layer access history
    std::unordered_map<int, std::vector<ExpertAccess>> accessHistory_;

    // Per-layer transition matrix: [fromExpert][toExpert] -> count
    std::unordered_map<int, std::unordered_map<int, uint64_t>> transitionCounts_;

    // Per-layer total transitions
    std::unordered_map<int, uint64_t> totalTransitions_;

    // Last accessed expert per layer
    std::unordered_map<int, int> lastExpert_;

    // Pending prefetches (for hit tracking)
    std::vector<std::pair<int, int>> pendingPrefetches_;  // (layer, expert)

    // Update transition matrix
    void updateTransition(int layerId, int fromExpert, int toExpert);

    // Compute transition probability
    float getTransitionProbability(int layerId, int fromExpert, int toExpert);
};

} // namespace Deep2

#endif // DEEP2_WARMUP_SCHEDULER_HPP