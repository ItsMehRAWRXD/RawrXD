#include "rawrxd/closure/ContextPlanner.hpp"
#include <algorithm>
#include <unordered_set>

namespace rawrxd::closure {

ContextSelection ContextPlanner::select(std::span<const ContextCandidate> candidates,
                                        uint32_t token_budget) {
    struct Scored { size_t i; double score; };
    std::vector<Scored> ranked;
    ranked.reserve(candidates.size());
    for (size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];
        if (!c.token_estimate || c.token_estimate > token_budget) continue;
        const double relevance =
            0.48 * c.symbol_score +
            0.32 * c.lexical_score +
            0.10 * c.recency_score +
            (c.dirty_buffer ? 0.10 : 0.0);
        // Mild size penalty prevents one giant file from crowding out several precise symbols.
        const double efficiency = relevance / (1.0 + static_cast<double>(c.token_estimate) / 4096.0);
        ranked.push_back({i, efficiency});
    }
    std::stable_sort(ranked.begin(), ranked.end(),
        [](const Scored& a, const Scored& b){ return a.score > b.score; });

    ContextSelection out;
    std::unordered_set<std::string> seen;
    for (const auto& r : ranked) {
        const auto& c = candidates[r.i];
        const std::string key = !c.id.empty() ? c.id : c.path;
        if (!seen.insert(key).second) continue;
        if (out.estimated_tokens + c.token_estimate > token_budget) continue;
        out.indices.push_back(r.i);
        out.estimated_tokens += c.token_estimate;
    }
    return out;
}

} // namespace rawrxd::closure
