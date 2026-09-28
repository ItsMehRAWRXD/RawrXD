// ============================================================================
// TimeReverseDigest.cpp — Reverse-time materialization scheduler implementation
// No blocking waits; purely event-driven with measured EMA.
// ============================================================================

#include "TimeReverseDigest.hpp"
#include <algorithm>
#include <cstdio>

namespace Deep2 {

TimeReverseDigest::TimeReverseDigest() = default;
TimeReverseDigest::~TimeReverseDigest() = default;

// ---------------------------------------------------------------------------
// Token lifecycle
// ---------------------------------------------------------------------------
void TimeReverseDigest::beginToken(uint64_t tokenIndex) {
    currentToken_.store(tokenIndex, std::memory_order_release);
}

void TimeReverseDigest::endToken(uint64_t /*tokenIndex*/) {
    tokensProcessed_.fetch_add(1, std::memory_order_relaxed);
    adaptHorizon();
}

// ---------------------------------------------------------------------------
// Observation: record actual measured durations via Beaconism
// ---------------------------------------------------------------------------
void TimeReverseDigest::observeExecution(uint32_t opId, uint64_t durationNs) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = ops_.find(opId);
    if (it == ops_.end()) return;
    auto tit = timing_.find(it->second.tensorId);
    if (tit == timing_.end()) {
        timing_[it->second.tensorId] = TensorTimingModel{};
        tit = timing_.find(it->second.tensorId);
    }
    updateEmaLocked(tit->second, tit->second.computeNs, durationNs);
}

void TimeReverseDigest::observeMaterialization(uint64_t tensorId,
                                                uint64_t readNs,
                                                uint64_t decryptNs,
                                                uint64_t uploadNs) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto tit = timing_.find(tensorId);
    if (tit == timing_.end()) {
        timing_[tensorId] = TensorTimingModel{};
        tit = timing_.find(tensorId);
    }
    updateEmaLocked(tit->second, tit->second.readNs, readNs);
    updateEmaLocked(tit->second, tit->second.decryptNs, decryptNs);
    updateEmaLocked(tit->second, tit->second.uploadNs, uploadNs);
    tit->second.lastUpdated = currentToken_.load(std::memory_order_acquire);
}

void TimeReverseDigest::observeGpuQueueLatency(uint64_t ns) {
    uint64_t old = gpuQueueLatencyNs_.load(std::memory_order_relaxed);
    uint64_t next = static_cast<uint64_t>(old * (1.0 - kEmaAlpha) + ns * kEmaAlpha);
    gpuQueueLatencyNs_.store(next, std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Plan registration
// ---------------------------------------------------------------------------
void TimeReverseDigest::registerOperation(const DigestedOperation& op) {
    std::lock_guard<std::mutex> lock(mtx_);
    ops_[op.opId] = op;
    tensorToOps_[op.tensorId].push_back(op.opId);
    if (tensorLastUse_.find(op.tensorId) == tensorLastUse_.end() ||
        op.lastUse > tensorLastUse_[op.tensorId]) {
        tensorLastUse_[op.tensorId] = op.lastUse;
    }
}

void TimeReverseDigest::clearPlan() {
    std::lock_guard<std::mutex> lock(mtx_);
    ops_.clear();
    tensorToOps_.clear();
    timing_.clear();
    pinCount_.clear();
    tensorLastUse_.clear();
}

// ---------------------------------------------------------------------------
// Deadline computation: reverse-time walk
// ---------------------------------------------------------------------------
uint64_t TimeReverseDigest::materializeAt(uint32_t opId, uint64_t tensorId) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = ops_.find(opId);
    if (it == ops_.end()) return 0;
    const uint64_t execDeadline = it->second.deadlineNs;
    const uint64_t matNs = estimateMaterializeNsLocked(tensorId);
    if (execDeadline <= matNs + kSafetyMarginNs) return 0;
    return execDeadline - matNs - kSafetyMarginNs;
}

bool TimeReverseDigest::ensureBeforeDeadline(uint32_t opId, uint64_t tensorId,
                                              uint64_t nowNs,
                                              MaterializationSchedule* outSchedule) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = ops_.find(opId);
    if (it == ops_.end()) return false;

    const uint64_t execDeadline = it->second.deadlineNs;
    const uint64_t matNs = estimateMaterializeNsLocked(tensorId);
    const uint64_t gpuReady = execDeadline - gpuQueueLatencyNs_.load(std::memory_order_relaxed);
    const uint64_t matStart = (gpuReady > matNs + kSafetyMarginNs)
                                  ? gpuReady - matNs - kSafetyMarginNs
                                  : 0;

    bool ok = (nowNs + matNs + kSafetyMarginNs) <= execDeadline;
    if (!ok) {
        lateMaterializations_.fetch_add(1, std::memory_order_relaxed);
        int64_t stall = static_cast<int64_t>(nowNs + matNs + kSafetyMarginNs - execDeadline);
        if (stall > 0)
            gpuStallNs_.fetch_add(static_cast<uint64_t>(stall), std::memory_order_relaxed);
    }

    if (outSchedule) {
        outSchedule->tensorId = tensorId;
        outSchedule->materializeStartNs = matStart;
        outSchedule->materializeDeadlineNs = gpuReady - gpuQueueLatencyNs_.load(std::memory_order_relaxed);
        outSchedule->gpuReadyDeadlineNs = gpuReady;
        outSchedule->executionDeadlineNs = execDeadline;
        outSchedule->criticalPath = (it->second.residency == ResidencyClass::Hot);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Scheduling horizon: only schedule ops within [now, now + horizon]
// ---------------------------------------------------------------------------
std::vector<MaterializationSchedule> TimeReverseDigest::scheduleFuture(
    uint64_t nowNs, uint64_t currentToken) {
    std::vector<MaterializationSchedule> out;
    const uint64_t horizon = horizonNs_.load(std::memory_order_acquire);

    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& kv : ops_) {
        const DigestedOperation& op = kv.second;
        if (op.firstUse > currentToken) continue; // not needed yet
        if (op.lastUse < currentToken) continue;  // already done

        const uint64_t execDeadline = op.deadlineNs;
        if (execDeadline <= nowNs) continue; // already past
        if (execDeadline > nowNs + horizon) continue; // outside horizon

        const uint64_t matNs = estimateMaterializeNsLocked(op.tensorId);
        const uint64_t gpuReady = execDeadline - gpuQueueLatencyNs_.load(std::memory_order_relaxed);
        const uint64_t matStart = (gpuReady > matNs + kSafetyMarginNs)
                                      ? gpuReady - matNs - kSafetyMarginNs
                                      : 0;

        MaterializationSchedule sch{};
        sch.tensorId = op.tensorId;
        sch.materializeStartNs = matStart;
        sch.materializeDeadlineNs = gpuReady - gpuQueueLatencyNs_.load(std::memory_order_relaxed);
        sch.gpuReadyDeadlineNs = gpuReady;
        sch.executionDeadlineNs = execDeadline;
        sch.criticalPath = (op.residency == ResidencyClass::Hot);
        out.push_back(sch);
    }
    std::sort(out.begin(), out.end(),
              [](const MaterializationSchedule& a, const MaterializationSchedule& b) {
                  return a.executionDeadlineNs < b.executionDeadlineNs;
              });
    return out;
}

// ---------------------------------------------------------------------------
// Residency lifecycle
// ---------------------------------------------------------------------------
void TimeReverseDigest::pinTensor(uint64_t tensorId, uint32_t /*opId*/) {
    std::lock_guard<std::mutex> lock(mtx_);
    ++pinCount_[tensorId];
}

void TimeReverseDigest::unlockTensor(uint64_t tensorId, uint32_t /*opId*/) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = pinCount_.find(tensorId);
    if (it != pinCount_.end()) {
        if (it->second > 0) --it->second;
    }
}

void TimeReverseDigest::retireCompleted(uint32_t opId) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = ops_.find(opId);
    if (it == ops_.end()) return;
    const uint64_t tensorId = it->second.tensorId;
    // If this op is the last_use, unlock and allow eviction
    auto lit = tensorLastUse_.find(tensorId);
    if (lit != tensorLastUse_.end() && lit->second == it->second.lastUse) {
        auto pit = pinCount_.find(tensorId);
        if (pit != pinCount_.end() && pit->second > 0) {
            --pit->second;
        }
    }
}

bool TimeReverseDigest::isTensorPinned(uint64_t tensorId) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = pinCount_.find(tensorId);
    return it != pinCount_.end() && it->second > 0;
}

// ---------------------------------------------------------------------------
// Slack measurement
// ---------------------------------------------------------------------------
std::vector<MaterializationSlack> TimeReverseDigest::computeSlack(uint64_t nowNs) const {
    std::vector<MaterializationSlack> out;
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& kv : ops_) {
        const DigestedOperation& op = kv.second;
        const uint64_t matNs = estimateMaterializeNsLocked(op.tensorId);
        const uint64_t readyBy = nowNs + matNs;
        MaterializationSlack sl{};
        sl.tensorId = op.tensorId;
        sl.opId = op.opId;
        sl.slackNs = static_cast<int64_t>(op.deadlineNs) - static_cast<int64_t>(readyBy);
        out.push_back(sl);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Adaptive horizon tuning
// ---------------------------------------------------------------------------
void TimeReverseDigest::adaptHorizon() {
    uint64_t late = lateMaterializations_.load(std::memory_order_relaxed);
    uint64_t early = earlyMaterializations_.load(std::memory_order_relaxed);
    uint64_t current = horizonNs_.load(std::memory_order_relaxed);

    if (late > 3) {
        // Too many late arrivals — widen horizon aggressively
        current = std::min<uint64_t>(current + current / 4, 50'000'000); // max 50 ms
        horizonNs_.store(current, std::memory_order_relaxed);
    } else if (early > 10 && late == 0) {
        // Too much early residence — shrink horizon
        current = std::max<uint64_t>(current - current / 10, 1'000'000); // min 1 ms
        horizonNs_.store(current, std::memory_order_relaxed);
    }
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------
std::string TimeReverseDigest::summary() const {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "TimeReverseDigest[tokens=%llu late=%llu early=%llu stallNs=%llu horizon=%.3fms]",
        static_cast<unsigned long long>(tokensProcessed_.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(lateMaterializations_.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(earlyMaterializations_.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(gpuStallNs_.load(std::memory_order_acquire)),
        horizonNs_.load(std::memory_order_acquire) / 1e6);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
uint64_t TimeReverseDigest::estimateMaterializeNsLocked(uint64_t tensorId) const {
    auto tit = timing_.find(tensorId);
    if (tit == timing_.end()) {
        // No measured data yet — use conservative defaults
        return 2'000'000; // 2 ms default
    }
    const TensorTimingModel& m = tit->second;
    return m.readNs + m.decryptNs + m.uploadNs;
}

void TimeReverseDigest::updateEmaLocked(TensorTimingModel& model,
                                        uint64_t& field,
                                        uint64_t measured) {
    (void)model;
    if (field == 0) {
        field = measured;
    } else {
        field = static_cast<uint64_t>(field * (1.0 - kEmaAlpha) + measured * kEmaAlpha);
    }
}

} // namespace Deep2
