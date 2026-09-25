#pragma once
// ============================================================================
// TimeReverseDigest.hpp — Reverse-time materialization scheduler
// Computes tensor residency deadlines backward from GPU execution deadlines.
// Never blocks on time; event-driven with measured EMA updates via Beaconism.
// ============================================================================

#include "Beaconism.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>

namespace Deep2 {

enum class ResidencyClass : uint8_t {
    Hot = 0,      // Always resident (embeddings, norms)
    Warm = 1,     // Current execution window
    Cool = 2,     // Future materialization window
    Cold = 3      // Spill / not resident
};

struct DigestedOperation {
    uint32_t opId = 0;
    uint32_t layer = 0;
    uint64_t tensorId = 0;
    uint32_t predecessor = 0;   // previous op in dependency chain
    uint32_t successor = 0;     // next op in dependency chain
    uint64_t expectedComputeNs = 0;
    uint64_t expectedReadNs = 0;
    uint64_t expectedDecryptNs = 0;
    uint64_t expectedUploadNs = 0;
    ResidencyClass residency = ResidencyClass::Cold;
    uint64_t firstUse = 0;      // token index of first use
    uint64_t lastUse = 0;       // token index of last use
    uint64_t deadlineNs = 0;    // absolute deadline for this op
};

struct TensorTimingModel {
    uint64_t readNs = 0;        // measured from Beaconism
    uint64_t decryptNs = 0;
    uint64_t uploadNs = 0;
    uint64_t computeNs = 0;
    uint64_t observedCount = 0; // EMA weight
    uint64_t lastUpdated = 0;   // token index of last observation
};

struct MaterializationSlack {
    int64_t slackNs = 0;        // negative = late (GPU stall), positive = early
    uint64_t tensorId = 0;
    uint32_t opId = 0;
};

struct MaterializationSchedule {
    uint64_t tensorId = 0;
    uint64_t materializeStartNs = 0;
    uint64_t materializeDeadlineNs = 0;
    uint64_t gpuReadyDeadlineNs = 0;
    uint64_t executionDeadlineNs = 0;
    bool criticalPath = false;
};

class TimeReverseDigest {
public:
    TimeReverseDigest();
    ~TimeReverseDigest();

    TimeReverseDigest(const TimeReverseDigest&) = delete;
    TimeReverseDigest& operator=(const TimeReverseDigest&) = delete;

    // -------------------------------------------------------------------------
    // Token lifecycle
    // -------------------------------------------------------------------------
    void beginToken(uint64_t tokenIndex);
    void endToken(uint64_t tokenIndex);

    // -------------------------------------------------------------------------
    // Observation: record actual measured durations (from Beaconism)
    // -------------------------------------------------------------------------
    void observeExecution(uint32_t opId, uint64_t durationNs);
    void observeMaterialization(uint64_t tensorId,
                                 uint64_t readNs,
                                 uint64_t decryptNs,
                                 uint64_t uploadNs);
    void observeGpuQueueLatency(uint64_t ns);

    // -------------------------------------------------------------------------
    // Plan registration (offline digestion)
    // -------------------------------------------------------------------------
    void registerOperation(const DigestedOperation& op);
    void clearPlan();

    // -------------------------------------------------------------------------
    // Deadline computation: reverse-time walk
    // -------------------------------------------------------------------------
    uint64_t materializeAt(uint32_t opId, uint64_t tensorId) const;
    bool ensureBeforeDeadline(uint32_t opId, uint64_t tensorId,
                              uint64_t nowNs,
                              MaterializationSchedule* outSchedule = nullptr);

    // -------------------------------------------------------------------------
    // Scheduling horizon: only schedule ops within [now, now + horizon]
    // -------------------------------------------------------------------------
    void setHorizonNs(uint64_t ns) { horizonNs_.store(ns, std::memory_order_release); }
    uint64_t horizonNs() const { return horizonNs_.load(std::memory_order_acquire); }

    // -------------------------------------------------------------------------
    // Residency lifecycle: pin / unlock / evict based on lastUse
    // -------------------------------------------------------------------------
    void pinTensor(uint64_t tensorId, uint32_t opId);
    void unlockTensor(uint64_t tensorId, uint32_t opId);
    void retireCompleted(uint32_t opId);
    bool isTensorPinned(uint64_t tensorId) const;

    // -------------------------------------------------------------------------
    // Forward scheduling: what must materialize now
    // -------------------------------------------------------------------------
    std::vector<MaterializationSchedule> scheduleFuture(
        uint64_t nowNs,
        uint64_t currentToken);

    // -------------------------------------------------------------------------
    // Slack measurement
    // -------------------------------------------------------------------------
    std::vector<MaterializationSlack> computeSlack(uint64_t nowNs) const;

    // -------------------------------------------------------------------------
    // Adaptive horizon tuning (based on observed slack)
    // -------------------------------------------------------------------------
    void adaptHorizon();

    // -------------------------------------------------------------------------
    // Diagnostics / telemetry
    // -------------------------------------------------------------------------
    uint64_t tokensProcessed() const { return tokensProcessed_.load(std::memory_order_acquire); }
    uint64_t lateMaterializations() const { return lateMaterializations_.load(std::memory_order_acquire); }
    uint64_t earlyMaterializations() const { return earlyMaterializations_.load(std::memory_order_acquire); }
    uint64_t gpuStallNs() const { return gpuStallNs_.load(std::memory_order_acquire); }

    // Summary for benchmark receipt
    std::string summary() const;

private:
    mutable std::mutex mtx_;

    // Plan
    std::unordered_map<uint32_t, DigestedOperation> ops_;
    std::unordered_map<uint64_t, std::vector<uint32_t>> tensorToOps_;

    // Timing model (EMA per tensor)
    std::unordered_map<uint64_t, TensorTimingModel> timing_;

    // Residency
    std::unordered_map<uint64_t, uint32_t> pinCount_;      // tensor -> refcount
    std::unordered_map<uint64_t, uint64_t> tensorLastUse_; // tensor -> last op

    // Scheduling state
    std::atomic<uint64_t> horizonNs_{5'000'000}; // 5 ms default
    std::atomic<uint64_t> currentToken_{0};
    std::atomic<uint64_t> tokensProcessed_{0};
    std::atomic<uint64_t> lateMaterializations_{0};
    std::atomic<uint64_t> earlyMaterializations_{0};
    std::atomic<uint64_t> gpuStallNs_{0};

    // Queue latency EMA
    std::atomic<uint64_t> gpuQueueLatencyNs_{100'000}; // 100 μs default
    static constexpr double kEmaAlpha = 0.2;

    // Safety margin
    static constexpr uint64_t kSafetyMarginNs = 50'000; // 50 μs

    // Internal helpers (caller holds mtx_)
    uint64_t estimateMaterializeNsLocked(uint64_t tensorId) const;
    void updateEmaLocked(TensorTimingModel& model,
                         uint64_t& field,
                         uint64_t measured);
};

} // namespace Deep2
