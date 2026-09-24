// ============================================================================
// ProductionProfiler.hpp — Real Runtime Profiling Provider
// ============================================================================
#pragma once
#include <atomic>
#include <cstdint>
#include <cmath>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Profile stage classification
// ---------------------------------------------------------------------------
enum class ProfilePhase : uint8_t {
    Idle = 0,
    Prefill = 1,
    Decode = 2,
    Tool = 3
};

// ---------------------------------------------------------------------------
// Per-token profile record
// ---------------------------------------------------------------------------
struct TokenProfile {
    uint32_t tokenId = 0;
    uint64_t seqId = 0;
    uint64_t modelEpoch = 0;
    ProfilePhase phase = ProfilePhase::Idle;
    uint64_t tokenLatencyNs = 0;      // total token time (embed + forward + sample)
    uint64_t gpuForwardNs = 0;        // GPU forward execution time
    uint64_t samplingNs = 0;          // sampling time
    uint64_t cpuOverheadNs = 0;       // CPU overhead (embedding, etc.)
    float observedTps = 0.0f;         // instantaneous TPS estimate
    std::string kernelName;           // primary kernel / path label
};

// ---------------------------------------------------------------------------
// Profile counters
// ---------------------------------------------------------------------------
struct ProfileCounters {
    uint64_t tokensStarted = 0;
    uint64_t tokensCompleted = 0;
    uint64_t tokensAborted = 0;

    uint64_t layersStarted = 0;
    uint64_t layersCompleted = 0;

    uint64_t prefillTokens = 0;
    uint64_t decodeTokens = 0;

    uint64_t cpuEvents = 0;
    uint64_t gpuEvents = 0;

    uint64_t profileSamples = 0;
    uint64_t invalidTransitions = 0;
};

// ---------------------------------------------------------------------------
// Derived timing statistics
// ---------------------------------------------------------------------------
struct TimingStats {
    uint64_t totalTokenNs = 0;
    uint64_t minTokenNs = UINT64_MAX;
    uint64_t maxTokenNs = 0;
    double   avgTokenNs = 0.0;
    double   emaTokenNs = 0.0;   // exponential moving average (alpha = 0.3)

    uint64_t totalGpuForwardNs = 0;
    uint64_t totalSamplingNs = 0;
    uint64_t totalCpuOverheadNs = 0;

    uint64_t prefillDurationNs = 0;
    uint64_t decodeDurationNs = 0;
    uint64_t totalWallNs = 0;

    double observedTps = 0.0;   // completed tokens / decode wall time (seconds)
};

// ---------------------------------------------------------------------------
// ProductionProfiler — real stateful profiling provider
// ---------------------------------------------------------------------------
class ProductionProfiler {
public:
    static constexpr size_t MAX_HISTORY = 4096;
    static constexpr double EMA_ALPHA = 0.3;

    ProductionProfiler() = default;
    ~ProductionProfiler() = default;

    // Lifecycle
    void reset();
    void onModelSwitch(uint64_t newEpoch);

    // Enable / disable
    bool isEnabled() const { return enabled_.load(std::memory_order_acquire); }
    void setEnabled(bool enable);

    // Token lifecycle
    void beginToken(uint32_t tokenId, uint64_t seqId, ProfilePhase phase);
    void endToken(uint32_t tokenId);
    void abortToken(uint32_t tokenId);

    // Stage timing records (called from instrumented paths)
    void recordGpuForward(uint64_t durationNs);
    void recordSampling(uint64_t durationNs);
    void recordCpuOverhead(uint64_t durationNs);

    // Layer lifecycle (consumed from Cyclone or direct)
    void beginLayer(uint32_t layer);
    void endLayer(uint32_t layer);

    // Statistics (thread-safe)
    ProfileCounters counters() const;
    TimingStats timing() const;
    size_t historySize() const;
    size_t historyEvictions() const;

    // History access
    const std::vector<TokenProfile>& history() const { return history_; }

    // JSON export
    std::string toJSON() const;
    bool saveJSON(const std::string& path) const;

private:
    mutable std::mutex mtx_;

    bool activeToken_ = false;
    uint32_t activeTokenId_ = 0;
    uint64_t activeSeqId_ = 0;
    ProfilePhase activePhase_ = ProfilePhase::Idle;
    uint64_t activeBeginNs_ = 0;
    uint64_t activeGpuForwardNs_ = 0;
    uint64_t activeSamplingNs_ = 0;
    uint64_t activeCpuOverheadNs_ = 0;

    uint64_t modelEpoch_ = 0;
    ProfileCounters counters_;
    TimingStats timing_;
    std::vector<TokenProfile> history_;
    size_t historyEvictions_ = 0;

    std::atomic<bool> enabled_{false};

    uint64_t nowNs() const;
    void flushActiveProfile();
    void addToHistory(const TokenProfile& tp);
    void updateTiming(const TokenProfile& tp);
};

} // namespace Deep2
