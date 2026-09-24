/* Chamber — SM0-DSP anomaly detector implementation */
#include "Chamber.hpp"
#include <algorithm>
#include <numeric>
#include <limits>

namespace Deep2 {

ChamberResult Chamber::evaluate(const float* hidden_state, size_t dim) {
    ++evaluationsTotal_;
    ChamberResult result;
    result.status = 0;
    result.flags = 0;
    result.severity = 0.0f;

    if (!hidden_state || dim == 0) {
        result.status = 1;
        result.flags |= 0x01; // null input
        result.severity = 1.0f;
        ++evaluationsAnomalous_;
        return result;
    }

    // Count non-finite values
    size_t nonFinite = 0;
    for (size_t i = 0; i < dim; ++i) {
        if (!std::isfinite(hidden_state[i])) {
            ++nonFinite;
            result.flags |= 0x02; // non-finite detected
        }
    }
    if (nonFinite > 0) {
        result.severity = std::max(result.severity,
            std::min(1.0f, static_cast<float>(nonFinite) / static_cast<float>(dim)));
    }

    // Compute mean and variance
    double sum = 0.0;
    double sumSq = 0.0;
    size_t validCount = 0;
    for (size_t i = 0; i < dim; ++i) {
        if (std::isfinite(hidden_state[i])) {
            double x = static_cast<double>(hidden_state[i]);
            sum += x;
            sumSq += x * x;
            ++validCount;
        }
    }
    if (validCount == 0) {
        result.status = 1;
        result.flags |= 0x04; // all non-finite
        result.severity = 1.0f;
        ++evaluationsAnomalous_;
        return result;
    }

    const double mean = sum / static_cast<double>(validCount);
    const double variance = (sumSq / validCount) - (mean * mean);
    const float varianceF = static_cast<float>(variance);

    // Dead neuron detection: near-zero variance
    if (varianceF <= deadNeuronThreshold_) {
        result.flags |= 0x08;
        result.severity = std::max(result.severity, 0.5f);
    }

    // Outlier detection using z-score
    if (varianceF > deadNeuronThreshold_) {
        const double stddev = std::sqrt(std::max(0.0, variance));
        size_t outliers = 0;
        for (size_t i = 0; i < dim; ++i) {
            if (std::isfinite(hidden_state[i])) {
                double z = std::abs((static_cast<double>(hidden_state[i]) - mean)
                                    / (stddev + 1e-12));
                if (z > outlierZ_) ++outliers;
            }
        }
        if (outliers > 0) {
            result.flags |= 0x10;
            float outlierRatio = static_cast<float>(outliers) / static_cast<float>(dim);
            result.severity = std::max(result.severity,
                std::min(1.0f, outlierRatio * 10.0f));
        }
    }

    // Entropy estimation (histogram binning for approximate entropy)
    {
        constexpr int bins = 64;
        int hist[bins] = {};
        float minVal = std::numeric_limits<float>::infinity();
        float maxVal = -std::numeric_limits<float>::infinity();
        for (size_t i = 0; i < dim; ++i) {
            if (std::isfinite(hidden_state[i])) {
                minVal = std::min(minVal, hidden_state[i]);
                maxVal = std::max(maxVal, hidden_state[i]);
            }
        }
        float range = maxVal - minVal;
        if (range > 1e-12f) {
            for (size_t i = 0; i < dim; ++i) {
                if (std::isfinite(hidden_state[i])) {
                    int b = static_cast<int>((hidden_state[i] - minVal) / range * (bins - 1));
                    b = std::clamp(b, 0, bins - 1);
                    ++hist[b];
                }
            }
            double entropy = 0.0;
            for (int b = 0; b < bins; ++b) {
                if (hist[b] > 0) {
                    double p = static_cast<double>(hist[b]) / static_cast<double>(validCount);
                    entropy -= p * std::log2(p);
                }
            }
            double maxEntropy = std::log2(static_cast<double>(bins));
            double normalizedEntropy = (maxEntropy > 0.0) ? (entropy / maxEntropy) : 0.0;
            if (normalizedEntropy < entropyMin_) {
                result.flags |= 0x20; // low entropy / collapsed distribution
                result.severity = std::max(result.severity,
                    static_cast<float>(1.0 - normalizedEntropy / entropyMin_));
            }
        }
    }

    if (result.flags != 0) {
        result.status = 1;
        ++evaluationsAnomalous_;
    }
    return result;
}

FormulaRoute Chamber::routePrimitive(uint64_t context_hash) const {
    FormulaRoute r;
    // Simple hash-based deterministic routing: low 3 bits select route 0–7
    r.route = static_cast<int>(context_hash & 0x07ULL);
    r.confidence = 0.5f + 0.5f * (static_cast<float>(r.route) / 7.0f);
    return r;
}

} // namespace Deep2
