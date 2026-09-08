#pragma once
#include "RawrTokenRate.hpp"

namespace Deep2 {

struct NsTokenRate {
    uint64_t nsPerToken = 0;
    double tps = 0.0;
    bool valid = false;
};

inline NsTokenRate MakeNsTokenRate(uint64_t nsPerToken) {
    if (nsPerToken == 0) return {0, 0.0, false};
    const GenerationBudget g{1, nsPerToken, kTokenBudgetNs5Tps};
    return {nsPerToken, g.tpsDerived(), true};
}

inline NsTokenRate RateFromWallTokens(uint64_t wallNs, uint64_t tokens) {
    const GenerationBudget g{tokens, wallNs, kTokenBudgetNs5Tps};
    if (!g.tokens || !g.wallNs) return {0, 0.0, false};
    return {g.nsPerToken(), g.tpsDerived(), true};
}

inline NsTokenRate RateFromCommitSpan(uint64_t firstCommitNs,
                                      uint64_t lastCommitNs,
                                      uint64_t commitCount) {
    if (commitCount == 0 || lastCommitNs < firstCommitNs)
        return {0, 0.0, false};
    return RateFromWallTokens(lastCommitNs - firstCommitNs, commitCount);
}

} // namespace Deep2
