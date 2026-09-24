// ============================================================================
// CycloneScheduler.cpp — Layer 0.2 real implementation
// ============================================================================
#include "CycloneScheduler.hpp"
#include <algorithm>
#include <limits>

namespace Deep2 {

// Global LivePath adapter binding; lifetime is strictly managed by
// Deep2Engine::enableCyclone/disableCyclone via LivePath_BindCyclone/UnbindCyclone.
CycloneScheduler* g_boundCyclone = nullptr;

CycloneScheduler::CycloneScheduler() = default;
CycloneScheduler::~CycloneScheduler() = default;

uint64_t CycloneScheduler::nowNs() const noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

void CycloneScheduler::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    perLayer_.clear();
    stats_ = CycloneStats{};
    activeLayer_ = UINT32_MAX;
    activeStartNs_ = 0;
    seq_ = 0;
    enabled_ = false;
}

void CycloneScheduler::onModelSwitch(uint32_t numLayers, uint64_t epoch) {
    std::lock_guard<std::mutex> lock(mtx_);
    perLayer_.clear();
    stats_ = CycloneStats{};
    activeLayer_ = UINT32_MAX;
    activeStartNs_ = 0;
    seq_ = 0;
    numLayers_ = numLayers;
    ++epoch_;
    if (epoch != 0) epoch_ = epoch;
    enabled_ = true;
}

bool CycloneScheduler::validateTransition(uint32_t layer, bool isStart) {
    if (isStart) {
        if (activeLayer_ != UINT32_MAX) {
            ++stats_.invalidTransitions;
            return false;
        }
        return true;
    } else {
        if (activeLayer_ == UINT32_MAX) {
            ++stats_.invalidTransitions;
            return false;
        }
        if (activeLayer_ != layer) {
            ++stats_.invalidTransitions;
            return false;
        }
        return true;
    }
}

void CycloneScheduler::updateEma(CycloneLayerStats& s, uint64_t durationNs) {
    if (s.emaNs == 0.0) {
        s.emaNs = static_cast<double>(durationNs);
    } else {
        const double a = s.emaAlpha;
        s.emaNs = a * static_cast<double>(durationNs) + (1.0 - a) * s.emaNs;
    }
}

void CycloneScheduler::onLayerStart(uint32_t layer, uint64_t seq) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!validateTransition(layer, true)) return;
    activeLayer_ = layer;
    activeStartNs_ = nowNs();
    seq_ = seq;
    ++stats_.layerStarts;
    auto& s = perLayer_[layer];
    ++s.starts;
    s.lastSeq = seq;
    s.lastEpoch = epoch_;
}

void CycloneScheduler::onLayerEnd(uint32_t layer, uint64_t seq, uint64_t durationNs) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!validateTransition(layer, false)) return;
    const uint64_t dur = durationNs ? durationNs : (nowNs() - activeStartNs_);
    activeLayer_ = UINT32_MAX;
    activeStartNs_ = 0;
    ++stats_.layerEnds;
    auto& s = perLayer_[layer];
    ++s.completes;
    s.totalNs += dur;
    s.minNs = std::min(s.minNs, dur);
    s.maxNs = std::max(s.maxNs, dur);
    updateEma(s, dur);
    s.lastSeq = seq;
    s.lastEpoch = epoch_;
}

void CycloneScheduler::onLayerAbort(uint32_t layer, uint64_t seq) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (activeLayer_ == UINT32_MAX) {
        ++stats_.invalidTransitions;
        return;
    }
    if (activeLayer_ != layer) {
        ++stats_.invalidTransitions;
        return;
    }
    activeLayer_ = UINT32_MAX;
    activeStartNs_ = 0;
    ++stats_.layerAborts;
    auto& s = perLayer_[layer];
    ++s.aborts;
    s.lastSeq = seq;
    s.lastEpoch = epoch_;
}

CyclonePrefetchDecision CycloneScheduler::decidePrefetch(uint32_t nextLayer, uint64_t /*seq*/) const {
    std::lock_guard<std::mutex> lock(mtx_);
    CyclonePrefetchDecision d;
    d.layer = nextLayer;
    ++const_cast<CycloneStats&>(stats_).schedulingDecisions;

    if (nextLayer + 1 >= numLayers_) {
        d.shouldPrefetch = false;
        return d;
    }

    const uint32_t prefetchLayer = nextLayer + 1;
    auto it = perLayer_.find(prefetchLayer);
    if (it == perLayer_.end() || it->second.emaNs == 0.0) {
        // No timing history — conservatively prefetch
        d.shouldPrefetch = true;
        d.leadDistance = 1;
        d.deadlineEpoch = epoch_ + 1;
        d.priority = 0;
        ++const_cast<CycloneStats&>(stats_).predictedPrefetches;
        return d;
    }

    const double ema = it->second.emaNs;
    const uint64_t remainingLayers = numLayers_ - nextLayer;
    const double estimatedTotalNs = ema * static_cast<double>(remainingLayers);

    // If estimated remaining time is very short, skip prefetch
    if (estimatedTotalNs < 1e6) { // < 1 ms
        d.shouldPrefetch = false;
        return d;
    }

    d.shouldPrefetch = true;
    d.leadDistance = 1;
    d.deadlineEpoch = epoch_ + 1;
    // Higher priority if EMA is large (takes longer, needs earlier start)
    d.priority = (ema > 1e7) ? 2 : ((ema > 1e6) ? 1 : 0);
    ++const_cast<CycloneStats&>(stats_).predictedPrefetches;
    return d;
}

CycloneLayerState CycloneScheduler::layerState(uint32_t layer) const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (activeLayer_ == layer) return CycloneLayerState::Running;
    auto it = perLayer_.find(layer);
    if (it == perLayer_.end()) return CycloneLayerState::Idle;
    if (it->second.aborts > 0 && it->second.completes == 0) return CycloneLayerState::Aborted;
    if (it->second.completes > 0) return CycloneLayerState::Complete;
    return CycloneLayerState::Idle;
}

double CycloneScheduler::layerEmaNs(uint32_t layer) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = perLayer_.find(layer);
    return (it != perLayer_.end()) ? it->second.emaNs : 0.0;
}

uint64_t CycloneScheduler::layerMinNs(uint32_t layer) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = perLayer_.find(layer);
    return (it != perLayer_.end() && it->second.minNs != UINT64_MAX) ? it->second.minNs : 0;
}

uint64_t CycloneScheduler::layerMaxNs(uint32_t layer) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = perLayer_.find(layer);
    return (it != perLayer_.end()) ? it->second.maxNs : 0;
}

} // namespace Deep2

