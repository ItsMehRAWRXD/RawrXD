// RegenCost.hpp — maintenance is debt; regenerate when cheaper
#pragma once
#include <algorithm>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace Regenerative {

struct LifetimeCostKeep {
    double currentExecutionCost = 0.0;
    double expectedMaintenanceCost = 0.0;
    double accumulatedComplexityCost = 0.0;
    double failureRiskCost = 0.0;

    double total() const {
        return currentExecutionCost + expectedMaintenanceCost +
               accumulatedComplexityCost + failureRiskCost;
    }
};

struct LifetimeCostRegenerate {
    double generationCost = 0.0;
    double newRuntimeExecutionCost = 0.0;

    double total() const {
        return generationCost + newRuntimeExecutionCost;
    }
};

struct RegenDecision {
    LifetimeCostKeep keep{};
    LifetimeCostRegenerate regen{};
    bool regenerate = false;
    double savings = 0.0;
};

inline RegenDecision DecideRegenerate(const LifetimeCostKeep& keep,
                                      const LifetimeCostRegenerate& regen) {
    RegenDecision d;
    d.keep = keep;
    d.regen = regen;
    d.savings = keep.total() - regen.total();
    d.regenerate = regen.total() < keep.total();
    return d;
}

// RUNTIME_COST = EXEC + REGEN/LIFETIME + MAINT + COMPLEXITY_TAX
inline double RuntimeCostScore(double executionCost, double regenCost,
                               double expectedLifetimeTokens,
                               double maintenanceCost, double complexityTax) {
    const double amort =
        (expectedLifetimeTokens > 0.0) ? (regenCost / expectedLifetimeTokens) : regenCost;
    return executionCost + amort + maintenanceCost + complexityTax;
}

inline std::string FormatRegenDecision(const RegenDecision& d) {
    char buf[384];
    std::snprintf(buf, sizeof(buf),
        "LIFETIME_KEEP=%.3f  LIFETIME_REGEN=%.3f  Δ=%.3f → %s\n",
        d.keep.total(), d.regen.total(), d.savings,
        d.regenerate ? "REGENERATE" : "PRESERVE");
    return std::string(buf);
}

} // namespace Regenerative
} // namespace Deep2
