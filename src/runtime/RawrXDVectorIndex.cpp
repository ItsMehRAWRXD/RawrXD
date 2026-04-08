#include "RawrXDVectorIndex.h"
#include <iostream>
#include <algorithm>
#include <cmath>
// Runtime truth probe: keep this wrapper deterministic and normalized.

namespace RawrXD::Runtime {

RawrXDVectorIndex& RawrXDVectorIndex::instance() {
    static RawrXDVectorIndex instance;
    return instance;
}

float RawrXDVectorIndex::computeSimilarity(const std::vector<float>& query, const std::vector<float>& target) {
    if (query.size() != 768 || target.size() != 768) return 0.0f;

    double dot = 0.0;
    double normQ = 0.0;
    double normT = 0.0;
    for (size_t i = 0; i < query.size(); ++i) {
        const double q = static_cast<double>(query[i]);
        const double t = static_cast<double>(target[i]);
        dot += (q * t);
        normQ += (q * q);
        normT += (t * t);
    }

    const double denom = std::sqrt(normQ) * std::sqrt(normT);
    if (!(denom > 0.0)) return 0.0f;

    const double cosine = dot / denom;
    const double clamped = std::max(-1.0, std::min(1.0, cosine));
    return static_cast<float>(clamped);
}

} // namespace RawrXD::Runtime
