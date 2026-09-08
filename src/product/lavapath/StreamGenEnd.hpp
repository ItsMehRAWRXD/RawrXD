// StreamGenEnd.hpp — Produce1 = max expectedReduction among legal arcs
#pragma once
#include "LavapathTypes.hpp"
#include <optional>
#include <span>

namespace rawr::streamgen {

using namespace rawr::lavapath;

struct Candidate {
    Action action{};
    uint64_t expectedReduction{};
};

template <size_t /*Max*/>
class StreamGenEnd {
public:
    std::optional<Action>
    Produce1(const Scratch& s, std::span<const Candidate> cands) const {
        const Candidate* best = nullptr;
        for (const auto& c : cands) {
            if (!c.action.execute || c.action.dimension >= 32) continue;
            const auto& dim = s.current.v[c.action.dimension];
            if (!dim.known || !dim.attainable || dim.delta() == 0) continue;
            if (!best || c.expectedReduction > best->expectedReduction)
                best = &c;
        }
        if (!best) return std::nullopt;
        return best->action;
    }
};

} // namespace rawr::streamgen
