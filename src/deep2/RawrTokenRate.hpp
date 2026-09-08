#pragma once
/* Performance primitive: WALL_NS <= TOKENS × TOKEN_BUDGET_NS.
   TPS is derived telemetry only — never the gate. */
#include "RawrNeed.hpp"
#include <cstdint>

namespace Deep2 {

inline constexpr uint64_t kNsPerSec = 1000000000ull;
inline constexpr uint64_t kTokenBudgetNs5Tps = 200000000ull;

constexpr uint64_t TokenBudgetNs(uint64_t targetTps) noexcept {
    return targetTps ? (kNsPerSec / targetTps) : 0;
}

struct GenerationBudget {
    uint64_t tokens = 0;
    uint64_t wallNs = 0;
    uint64_t budgetNsPerToken = kTokenBudgetNs5Tps;

    constexpr uint64_t allowedWallNs() const noexcept {
        return tokens * budgetNsPerToken;
    }

    constexpr uint64_t budgetNs() const noexcept { return allowedWallNs(); }

    constexpr RawrNeed asNeed() const noexcept {
        return WallBudgetNeed(allowedWallNs(), wallNs);
    }

    constexpr uint64_t deficitNs() const noexcept {
        return rawrMissing(asNeed());
    }

    constexpr int64_t slackNs() const noexcept {
        return static_cast<int64_t>(allowedWallNs()) -
               static_cast<int64_t>(wallNs);
    }

    constexpr bool hasTokens() const noexcept { return tokens > 0; }

    constexpr bool withinBudget() const noexcept {
        return hasTokens() &&
               rawrSatisfied(asNeed()) == RawrState::Satisfied;
    }

    constexpr bool pass() const noexcept {
        return tokens != 0 && wallNs != 0 && withinBudget();
    }

    constexpr uint64_t nsPerToken() const noexcept {
        return (tokens && wallNs) ? (wallNs / tokens) : 0;
    }

    double tpsDerived() const noexcept {
        return (tokens && wallNs)
            ? (double(tokens) * double(kNsPerSec)) / double(wallNs)
            : 0.0;
    }
    double tpsReal() const noexcept { return tpsDerived(); }
};

using RawrTokenRate = GenerationBudget;

struct RawrRateTarget {
    uint64_t tpsNumerator = 5;
    uint64_t tpsDenominator = 1;

    constexpr uint64_t targetNsPerToken() const noexcept {
        if (tpsNumerator == 0) return 0;
        return (kNsPerSec * tpsDenominator) / tpsNumerator;
    }

    constexpr bool pass(uint64_t tokens, uint64_t wallNs) const noexcept {
        return GenerationBudget{tokens, wallNs, targetNsPerToken()}.pass();
    }
};

inline constexpr uint64_t kCapacityTargetNsToken = kTokenBudgetNs5Tps;
inline constexpr uint64_t kTargetNsPerToken5 = kTokenBudgetNs5Tps;

inline bool CapacityNsMeetsFloor(uint64_t capacityNsToken,
                                 uint64_t targetNs = kTokenBudgetNs5Tps) {
    return capacityNsToken != 0 && capacityNsToken <= targetNs;
}

} // namespace Deep2
