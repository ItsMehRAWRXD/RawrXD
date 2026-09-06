// PhysicalHotpatchEngine.hpp — debt-consuming hotpatch loop façade
#pragma once
#include "PhysicalHotpatch.hpp"
#include "StallCausalGraph.hpp"
#include "TargetTokenBudget.hpp"
#include "TimeReversalEngine.hpp"

namespace Deep2 {
namespace TimeReversal {

struct ReversePerfDashboard {
    TimeDebtSnapshot debt{};
    ClassifiedBudget classes{};
    PortfolioPlan portfolio{};
    ResourceOpportunity opportunity{};
    double tpsValueNow = 0.0;
    double tpsValueAtTarget = 0.0;
    PhysicalHotpatchRequirement requirement{};
    char text[2048]{};
};

class PhysicalHotpatchEngine {
public:
    explicit PhysicalHotpatchEngine(EngineConfig cfg = {});

    TimeReversalEngine& Core() { return core_; }
    const TimeReversalEngine& Core() const { return core_; }

    void SetTargetTps(double tps);
    void SetClassifiedBudget(double essentialMs, double avoidableMs,
                             double movementMs, double stallMs);
    void SetStallGraph(const StallGraph& g);

    TimeDebtAccount& Account() { return account_; }
    void ObserveTokenMs(double measuredMs);

    ReversePerfDashboard BuildDashboard(const PortfolioBid* bids, int nBids,
                                        uint64_t nowMs) const;

    PhysicalHotpatchResult ApplyMeasuredPatch(
        uint64_t genBefore, uint64_t genAfter,
        double beforeMs, double afterMs,
        double patchOverheadMs,
        bool outputEquivalent, bool authorityUnchanged,
        double cpathBeforeUs, double cpathAfterUs);

private:
    TimeReversalEngine core_;
    TimeDebtAccount account_{};
    ClassifiedBudget classes_{};
    StallGraph stalls_{};
    double targetMs_ = 0.0;
};

} // namespace TimeReversal
} // namespace Deep2
