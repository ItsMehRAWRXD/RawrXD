#pragma once
#include "../complete/candidate_rank.hpp"
#include <string>
namespace rawr::product {

struct GhostText {
    std::string text;
    int accepted = 0;
    int stale = 0;
    uint64_t gen = 0;
};

inline GhostText MakeGhost(uint64_t gen, const Candidate& best) {
    GhostText g;
    g.gen = gen;
    g.text = best.text;
    g.accepted = 0;
    return g;
}

inline bool GhostLive(const GhostText& g, uint64_t liveGen) {
    return g.gen == liveGen && !g.stale && !g.text.empty();
}

inline void GhostOnGen(GhostText& g, uint64_t liveGen) {
    if (g.gen != liveGen) g.stale = 1;
}

inline void GhostReject(GhostText& g) {
    g.stale = 1;
    g.accepted = 0;
}

inline bool GhostAcceptLive(GhostText& g, uint64_t liveGen) {
    if (!GhostLive(g, liveGen)) return false;
    g.accepted = 1;
    return true;
}

} // namespace rawr::product
