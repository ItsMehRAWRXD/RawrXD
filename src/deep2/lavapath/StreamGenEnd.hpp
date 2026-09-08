#pragma once
/* Produce1 among legal candidates — no plan array, no timer. */
#include "Lavapath.hpp"
#include <cstddef>
#include <optional>

namespace rawr::streamgen {

using rawr::lavapath::Action;
using rawr::lavapath::Scratch;

struct Candidate {
    Action action{};
    uint64_t expectedReduction = 0;
};

template <size_t N = 32>
inline std::optional<Action> Produce1(const Scratch<N>& s,
                                      const Candidate* cands,
                                      size_t n) noexcept {
    const Candidate* best = nullptr;
    for (size_t i = 0; i < n; ++i) {
        const Candidate& c = cands[i];
        if (!c.action.execute) continue;
        if (c.action.dimension >= N) continue;
        const auto& dim = s.current.v[c.action.dimension];
        if (!dim.known || !dim.attainable || dim.delta() == 0) continue;
        if (!best || c.expectedReduction > best->expectedReduction)
            best = &c;
    }
    if (!best) return std::nullopt;
    return best->action;
}

} // namespace rawr::streamgen
