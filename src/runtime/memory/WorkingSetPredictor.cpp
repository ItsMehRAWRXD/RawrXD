// ============================================================================
// WorkingSetPredictor.cpp
// ============================================================================
#include "WorkingSetPredictor.hpp"
#include <algorithm>
#include <cmath>

namespace RawrXD {
namespace Memory {

WorkingSetPredictor::WorkingSetPredictor(uint32_t lookaheadDepth)
    : m_lookaheadDepth(lookaheadDepth) {}

void WorkingSetPredictor::recordAccess(const AccessRecord& rec) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto& s = m_stats[rec.id];
    if (s.accessCount > 0) {
        // Compute observed reuse distance in layers.
        uint32_t dist = (rec.layer >= s.lastLayer)
                      ? (rec.layer - s.lastLayer)
                      : UINT32_MAX;
        s.observedReuse = (s.observedReuse == UINT32_MAX)
                        ? dist
                        : (s.observedReuse + dist) / 2;   // running average
    }
    s.prevLayer       = s.lastLayer;
    s.lastLayer       = rec.layer;
    s.totalTransferNs += rec.transferTimeNs;
    s.totalBytes      += rec.bytes;
    s.accessCount     += 1;
}

void WorkingSetPredictor::advanceLayer(uint32_t layer) {
    std::unique_lock<std::mutex> lk(m_mtx);
    m_currentLayer = layer;
    m_layersSinceReset++;
    if (m_layersSinceReset >= kPressureWindow) {
        m_evictionsRecent = 0;
        m_layersSinceReset = 0;
    }
}

std::vector<TensorPrediction> WorkingSetPredictor::predict(uint32_t currentLayer) const {
    std::unique_lock<std::mutex> lk(m_mtx);
    double pressure = 0.0;
    if (m_layersSinceReset > 0)
        pressure = std::min(1.0, static_cast<double>(m_evictionsRecent) /
                                 static_cast<double>(m_layersSinceReset));

    std::vector<TensorPrediction> out;
    out.reserve(m_stats.size());
    for (auto& [id, s] : m_stats) {
        if (s.observedReuse == UINT32_MAX) continue;
        uint32_t nextLayer = s.lastLayer + s.observedReuse;
        if (nextLayer < currentLayer) continue;            // already past
        if (nextLayer > currentLayer + m_lookaheadDepth) continue;

        TensorPrediction tp;
        tp.id                = id;
        tp.lastLayer         = s.lastLayer;
        tp.nextPredictedLayer = nextLayer;
        tp.reuseDistance     = s.observedReuse;
        tp.score             = computeScore(s, currentLayer, pressure);

        // Normalised transfer cost: 0 = expensive (long avg transfer), 1 = free.
        double avgTransferMs = (s.accessCount > 0 && s.totalBytes > 0)
                             ? static_cast<double>(s.totalTransferNs) /
                               static_cast<double>(s.accessCount * 1'000'000)
                             : 0.0;
        tp.transferCostNorm  = 1.0 / (1.0 + avgTransferMs);

        out.push_back(tp);
    }
    // Sort by descending score (highest priority first).
    std::sort(out.begin(), out.end(),
              [](const TensorPrediction& a, const TensorPrediction& b){
                  return a.score > b.score;
              });
    return out;
}

TensorPrediction WorkingSetPredictor::predictionFor(TensorId id) const {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_stats.find(id);
    if (it == m_stats.end()) {
        TensorPrediction tp; tp.id = id; tp.score = 0; return tp;
    }
    double pressure = 0.0;
    if (m_layersSinceReset > 0)
        pressure = std::min(1.0, static_cast<double>(m_evictionsRecent) /
                                 static_cast<double>(m_layersSinceReset));

    const auto& s = it->second;
    TensorPrediction tp;
    tp.id                = id;
    tp.lastLayer         = s.lastLayer;
    tp.nextPredictedLayer = (s.observedReuse == UINT32_MAX)
                          ? UINT32_MAX
                          : s.lastLayer + s.observedReuse;
    tp.reuseDistance     = s.observedReuse;
    tp.score             = computeScore(s, m_currentLayer, pressure);

    double avgTransferMs = (s.accessCount > 0 && s.totalBytes > 0)
                         ? static_cast<double>(s.totalTransferNs) /
                           static_cast<double>(s.accessCount * 1'000'000)
                         : 0.0;
    tp.transferCostNorm  = 1.0 / (1.0 + avgTransferMs);
    return tp;
}

double WorkingSetPredictor::memoryPressure() const {
    std::unique_lock<std::mutex> lk(m_mtx);
    if (m_layersSinceReset == 0) return 0.0;
    return std::min(1.0, static_cast<double>(m_evictionsRecent) /
                         static_cast<double>(m_layersSinceReset));
}

void WorkingSetPredictor::notifyEviction() {
    std::unique_lock<std::mutex> lk(m_mtx);
    m_evictionsRecent++;
}

uint32_t WorkingSetPredictor::computeScore(const TensorStats& s,
                                           uint32_t currentLayer,
                                           double pressure) const noexcept {
    if (s.accessCount == 0 || s.observedReuse == UINT32_MAX) return 0;

    // execution_probability: 1 if used at least once and reuse pattern known.
    double execProb = 1.0;

    // reuse_probability: decays with reuse distance.
    double reuseDist = static_cast<double>(s.observedReuse);
    double reuseProb = std::exp(-reuseDist / 10.0);  // half-life ~7 layers

    // transfer_cost factor: average transfer time normalised to [0, 1].
    double avgTransferMs = (s.accessCount > 0 && s.totalBytes > 0)
                         ? static_cast<double>(s.totalTransferNs) /
                           static_cast<double>(s.accessCount * 1'000'000)
                         : 0.0;
    double xferCost = 1.0 / (1.0 + avgTransferMs);

    double score = execProb * reuseProb * xferCost * (1.0 - pressure);
    score = std::max(0.0, std::min(1.0, score));
    return static_cast<uint32_t>(score * 1000.0);
}

} // namespace Memory
} // namespace RawrXD
