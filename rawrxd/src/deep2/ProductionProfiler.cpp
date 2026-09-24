// ============================================================================
// ProductionProfiler.cpp — Real Runtime Profiling Provider
// ============================================================================
#include "ProductionProfiler.hpp"
#include <chrono>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Monotonic clock helper
// ---------------------------------------------------------------------------
uint64_t ProductionProfiler::nowNs() const {
    auto now = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()
        ).count()
    );
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
void ProductionProfiler::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    activeToken_ = false;
    activeTokenId_ = 0;
    activeSeqId_ = 0;
    activePhase_ = ProfilePhase::Idle;
    activeBeginNs_ = 0;
    activeGpuForwardNs_ = 0;
    activeSamplingNs_ = 0;
    activeCpuOverheadNs_ = 0;

    counters_ = ProfileCounters{};
    timing_ = TimingStats{};
    timing_.minTokenNs = UINT64_MAX;
    history_.clear();
    historyEvictions_ = 0;
    // modelEpoch_ intentionally retained across reset unless caller changes it
}

void ProductionProfiler::onModelSwitch(uint64_t newEpoch) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (activeToken_) {
        // Abort active profile on model switch
        flushActiveProfile();
        ++counters_.tokensAborted;
        activeToken_ = false;
    }
    modelEpoch_ = newEpoch;
}

// ---------------------------------------------------------------------------
// Enable / disable
// ---------------------------------------------------------------------------
void ProductionProfiler::setEnabled(bool enable) {
    if (!enable) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (activeToken_) {
            flushActiveProfile();
            ++counters_.tokensAborted;
            activeToken_ = false;
        }
        enabled_.store(false, std::memory_order_release);
        return;
    }
    enabled_.store(true, std::memory_order_release);
}

// ---------------------------------------------------------------------------
// Token lifecycle
// ---------------------------------------------------------------------------
void ProductionProfiler::beginToken(uint32_t tokenId, uint64_t seqId, ProfilePhase phase) {
    if (!enabled_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lock(mtx_);
    if (activeToken_) {
        ++counters_.invalidTransitions;
        return; // reject double-begin
    }
    activeToken_ = true;
    activeTokenId_ = tokenId;
    activeSeqId_ = seqId;
    activePhase_ = phase;
    activeBeginNs_ = nowNs();
    activeGpuForwardNs_ = 0;
    activeSamplingNs_ = 0;
    activeCpuOverheadNs_ = 0;
    ++counters_.tokensStarted;

    if (phase == ProfilePhase::Prefill) {
        ++counters_.prefillTokens;
    } else if (phase == ProfilePhase::Decode) {
        ++counters_.decodeTokens;
    }
}

void ProductionProfiler::endToken(uint32_t tokenId) {
    if (!enabled_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lock(mtx_);
    if (!activeToken_) {
        ++counters_.invalidTransitions;
        return; // end without begin
    }
    if (activeTokenId_ != tokenId) {
        ++counters_.invalidTransitions;
        return; // mismatched token id
    }

    uint64_t now = nowNs();
    uint64_t latency = (now > activeBeginNs_) ? (now - activeBeginNs_) : 0;

    TokenProfile tp;
    tp.tokenId = tokenId;
    tp.seqId = activeSeqId_;
    tp.modelEpoch = modelEpoch_;
    tp.phase = activePhase_;
    tp.tokenLatencyNs = latency;
    tp.gpuForwardNs = activeGpuForwardNs_;
    tp.samplingNs = activeSamplingNs_;
    tp.cpuOverheadNs = activeCpuOverheadNs_;

    updateTiming(tp);
    addToHistory(tp);

    ++counters_.tokensCompleted;
    ++counters_.profileSamples;
    activeToken_ = false;
}

void ProductionProfiler::abortToken(uint32_t tokenId) {
    if (!enabled_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lock(mtx_);
    if (!activeToken_) {
        ++counters_.invalidTransitions;
        return; // abort without begin
    }
    if (activeTokenId_ != tokenId) {
        ++counters_.invalidTransitions;
        return; // mismatched token id
    }

    flushActiveProfile();
    ++counters_.tokensAborted;
    activeToken_ = false;
}

// ---------------------------------------------------------------------------
// Stage timing records
// ---------------------------------------------------------------------------
void ProductionProfiler::recordGpuForward(uint64_t durationNs) {
    if (!enabled_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lock(mtx_);
    if (!activeToken_) return;
    activeGpuForwardNs_ += durationNs;
    ++counters_.gpuEvents;
}

void ProductionProfiler::recordSampling(uint64_t durationNs) {
    if (!enabled_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lock(mtx_);
    if (!activeToken_) return;
    activeSamplingNs_ += durationNs;
    ++counters_.cpuEvents;
}

void ProductionProfiler::recordCpuOverhead(uint64_t durationNs) {
    if (!enabled_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lock(mtx_);
    if (!activeToken_) return;
    activeCpuOverheadNs_ += durationNs;
    ++counters_.cpuEvents;
}

// ---------------------------------------------------------------------------
// Layer lifecycle
// ---------------------------------------------------------------------------
void ProductionProfiler::beginLayer(uint32_t /*layer*/) {
    if (!enabled_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lock(mtx_);
    ++counters_.layersStarted;
}

void ProductionProfiler::endLayer(uint32_t /*layer*/) {
    if (!enabled_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lock(mtx_);
    ++counters_.layersCompleted;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
void ProductionProfiler::flushActiveProfile() {
    uint64_t now = nowNs();
    uint64_t latency = (now > activeBeginNs_) ? (now - activeBeginNs_) : 0;

    TokenProfile tp;
    tp.tokenId = activeTokenId_;
    tp.seqId = activeSeqId_;
    tp.modelEpoch = modelEpoch_;
    tp.phase = activePhase_;
    tp.tokenLatencyNs = latency;
    tp.gpuForwardNs = activeGpuForwardNs_;
    tp.samplingNs = activeSamplingNs_;
    tp.cpuOverheadNs = activeCpuOverheadNs_;

    addToHistory(tp);
}

void ProductionProfiler::addToHistory(const TokenProfile& tp) {
    if (history_.size() >= MAX_HISTORY) {
        history_.erase(history_.begin());
        ++historyEvictions_;
    }
    history_.push_back(tp);
}

void ProductionProfiler::updateTiming(const TokenProfile& tp) {
    uint64_t lat = tp.tokenLatencyNs;
    timing_.totalTokenNs += lat;
    if (lat < timing_.minTokenNs) timing_.minTokenNs = lat;
    if (lat > timing_.maxTokenNs) timing_.maxTokenNs = lat;

    timing_.totalGpuForwardNs += tp.gpuForwardNs;
    timing_.totalSamplingNs += tp.samplingNs;
    timing_.totalCpuOverheadNs += tp.cpuOverheadNs;

    if (tp.phase == ProfilePhase::Prefill) {
        timing_.prefillDurationNs += lat;
    } else if (tp.phase == ProfilePhase::Decode) {
        timing_.decodeDurationNs += lat;
    }
    timing_.totalWallNs += lat;

    // EMA update
    if (timing_.emaTokenNs == 0.0 && counters_.tokensCompleted == 0) {
        timing_.emaTokenNs = static_cast<double>(lat);
    } else {
        timing_.emaTokenNs = EMA_ALPHA * static_cast<double>(lat)
                           + (1.0 - EMA_ALPHA) * timing_.emaTokenNs;
    }

    // Average
    size_t n = counters_.tokensCompleted + 1; // after this completion
    timing_.avgTokenNs = static_cast<double>(timing_.totalTokenNs) / static_cast<double>(n);

    // Observed TPS from decode phase only
    if (timing_.decodeDurationNs > 0) {
        timing_.observedTps =
            static_cast<double>(counters_.decodeTokens) /
            (static_cast<double>(timing_.decodeDurationNs) / 1e9);
    }
}

// ---------------------------------------------------------------------------
// Statistics readers
// ---------------------------------------------------------------------------
ProfileCounters ProductionProfiler::counters() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return counters_;
}

TimingStats ProductionProfiler::timing() const {
    std::lock_guard<std::mutex> lock(mtx_);
    TimingStats t = timing_;
    if (t.minTokenNs == UINT64_MAX) t.minTokenNs = 0;
    return t;
}

size_t ProductionProfiler::historySize() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return history_.size();
}

size_t ProductionProfiler::historyEvictions() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return historyEvictions_;
}

// ---------------------------------------------------------------------------
// JSON export
// ---------------------------------------------------------------------------
std::string ProductionProfiler::toJSON() const {
    std::lock_guard<std::mutex> lock(mtx_);

    std::ostringstream oss;
    oss << std::setprecision(6) << std::fixed;
    oss << "{\n";
    oss << "  \"model_epoch\": " << modelEpoch_ << ",\n";
    oss << "  \"tokens_started\": " << counters_.tokensStarted << ",\n";
    oss << "  \"tokens_completed\": " << counters_.tokensCompleted << ",\n";
    oss << "  \"tokens_aborted\": " << counters_.tokensAborted << ",\n";
    oss << "  \"prefill_tokens\": " << counters_.prefillTokens << ",\n";
    oss << "  \"decode_tokens\": " << counters_.decodeTokens << ",\n";
    oss << "  \"profile_samples\": " << counters_.profileSamples << ",\n";

    uint64_t minNs = (timing_.minTokenNs == UINT64_MAX) ? 0 : timing_.minTokenNs;
    oss << "  \"average_token_ns\": " << timing_.avgTokenNs << ",\n";
    oss << "  \"min_token_ns\": " << minNs << ",\n";
    oss << "  \"max_token_ns\": " << timing_.maxTokenNs << ",\n";
    oss << "  \"ema_token_ns\": " << timing_.emaTokenNs << ",\n";
    oss << "  \"observed_tps\": " << timing_.observedTps << ",\n";
    oss << "  \"gpu_forward_ns\": " << timing_.totalGpuForwardNs << ",\n";
    oss << "  \"sampling_ns\": " << timing_.totalSamplingNs << ",\n";
    oss << "  \"cpu_overhead_ns\": " << timing_.totalCpuOverheadNs << ",\n";
    oss << "  \"prefill_duration_ns\": " << timing_.prefillDurationNs << ",\n";
    oss << "  \"decode_duration_ns\": " << timing_.decodeDurationNs << ",\n";
    oss << "  \"total_wall_ns\": " << timing_.totalWallNs << ",\n";
    oss << "  \"gpu_events\": " << counters_.gpuEvents << ",\n";
    oss << "  \"cpu_events\": " << counters_.cpuEvents << ",\n";
    oss << "  \"layers_started\": " << counters_.layersStarted << ",\n";
    oss << "  \"layers_completed\": " << counters_.layersCompleted << ",\n";
    oss << "  \"invalid_transitions\": " << counters_.invalidTransitions << ",\n";
    oss << "  \"history_size\": " << history_.size() << ",\n";
    oss << "  \"history_evictions\": " << historyEvictions_ << "\n";
    oss << "}\n";
    return oss.str();
}

bool ProductionProfiler::saveJSON(const std::string& path) const {
    std::ofstream ofs(path);
    if (!ofs.is_open()) return false;
    ofs << toJSON();
    ofs.close();
    return ofs.good();
}

} // namespace Deep2
