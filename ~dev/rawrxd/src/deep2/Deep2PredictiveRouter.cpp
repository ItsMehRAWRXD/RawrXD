#include "Deep2PredictiveRouter.hpp"
#include <algorithm>

namespace Deep2::Roofline {

void PredictiveRouter::observe(u32 layer, const std::vector<u32>& experts) {
    auto& s = layers_[layer];
    for (u32 e : experts) ++s.frequency[e];
    s.last = experts;
}

std::vector<u32> PredictiveRouter::predict(u32 layer, u32 maxExperts) const {
    std::vector<u32> out;
    auto it = layers_.find(layer);
    if (it == layers_.end() || !maxExperts) return out;
    std::vector<std::pair<u32, u64>> ranked(it->second.frequency.begin(), it->second.frequency.end());
    std::stable_sort(ranked.begin(), ranked.end(), [&](const auto& a, const auto& b) {
        const bool alast = std::find(it->second.last.begin(), it->second.last.end(), a.first) != it->second.last.end();
        const bool blast = std::find(it->second.last.begin(), it->second.last.end(), b.first) != it->second.last.end();
        if (alast != blast) return alast > blast;
        return a.second > b.second;
    });
    for (const auto& p : ranked) {
        out.push_back(p.first);
        if (out.size() >= maxExperts) break;
    }
    return out;
}

void PredictiveRouter::reset() { layers_.clear(); }

} // namespace Deep2::Roofline
