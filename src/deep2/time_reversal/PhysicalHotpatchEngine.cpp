// PhysicalHotpatchEngine.cpp — debt consume loop
#include "PhysicalHotpatchEngine.hpp"
#include <cstdio>

namespace Deep2 {
namespace TimeReversal {

PhysicalHotpatchEngine::PhysicalHotpatchEngine(EngineConfig cfg) : core_(cfg) {}

void PhysicalHotpatchEngine::SetTargetTps(double tps) {
    core_.SetTargetTps(tps);
    targetMs_ = MsPerTokenFromTps(tps);
}

void PhysicalHotpatchEngine::SetClassifiedBudget(double essentialMs,
                                                 double avoidableMs,
                                                 double movementMs,
                                                 double stallMs) {
    classes_ = ClassifyBudget(essentialMs, avoidableMs, movementMs, stallMs,
                              targetMs_);
}

void PhysicalHotpatchEngine::SetStallGraph(const StallGraph& g) { stalls_ = g; }

void PhysicalHotpatchEngine::ObserveTokenMs(double measuredMs) {
    if (targetMs_ <= 0.0) return;
    account_.ObserveToken(measuredMs, targetMs_);
}

ReversePerfDashboard PhysicalHotpatchEngine::BuildDashboard(
    const PortfolioBid* bids, int nBids, uint64_t nowMs) const {
    ReversePerfDashboard d;
    const auto w = core_.Windows(nowMs);
    const double curMs = w.last10s.meanMsPerToken > 0.0
                             ? w.last10s.meanMsPerToken
                             : (classes_.totalMs > 0.0 ? classes_.totalMs : 28.20);
    d.debt = MakeDebt(curMs, targetMs_);
    d.classes = classes_;
    d.portfolio = BuildPortfolio(d.debt.debtMs, bids, nBids, 1.15);
    d.opportunity = core_.Opportunity();
    d.tpsValueNow = TpsValueOfOneMs(curMs);
    d.tpsValueAtTarget = TpsValueOfOneMs(targetMs_);
    d.requirement = MakeHotpatchRequirement(
        curMs, targetMs_, d.portfolio.confidenceNetMs, 0.0, 0.0);

    std::snprintf(d.text, sizeof(d.text),
        "╔══════ RAWRXD REVERSE PERFORMANCE ENGINE ══════╗\n"
        "CURRENT  %.2f TPS   %.2f ms/token\n"
        "TARGET   %.2f TPS   %.2f ms/token\n"
        "REQUIRED throughput +%.1f%%  latency -%.1f%%  debt %.2f ms\n"
        "FLOOR    essential %.2f  ceiling %.2f TPS  headroom %.2f\n"
        "REMOVABLE %.2f  recovery_need %.1f%%\n"
        "SAVINGS  raw %.2f  conf %.2f  certainty %s\n"
        "TIME_VALUE now %.2f TPS/ms  target-region %.2f TPS/ms\n"
        "UNPAID_DEBT_ACCOUNT %.2f ms over %llu tokens\n"
        "╚════════════════════════════════════════════════╝\n",
        TpsFromMsPerToken(curMs), curMs,
        TpsFromMsPerToken(targetMs_), targetMs_,
        100.0 * (d.debt.throughputRequired - 1.0),
        100.0 * d.debt.latencyReduction, d.debt.debtMs,
        d.classes.essentialMs, d.classes.theoreticalMaxTps,
        d.classes.targetHeadroomMs, d.classes.removableMs,
        100.0 * RecoveryFractionRequired(d.debt.debtMs, d.classes.removableMs),
        d.portfolio.rawNetMs, d.portfolio.confidenceNetMs,
        d.portfolio.confidenceFeasible ? "PASS" : "INSUFFICIENT",
        d.tpsValueNow, d.tpsValueAtTarget,
        account_.unpaidDebtMs,
        static_cast<unsigned long long>(account_.tokens));
    (void)nowMs;
    return d;
}

PhysicalHotpatchResult PhysicalHotpatchEngine::ApplyMeasuredPatch(
    uint64_t genBefore, uint64_t genAfter,
    double beforeMs, double afterMs,
    double patchOverheadMs,
    bool outputEquivalent, bool authorityUnchanged,
    double cpathBeforeUs, double cpathAfterUs) {
    auto r = MeasureHotpatch(genBefore, genAfter, beforeMs, afterMs, targetMs_,
                             patchOverheadMs, outputEquivalent,
                             authorityUnchanged, cpathBeforeUs, cpathAfterUs);
    if (r.physicalTimeRemovedMs > 0.0)
        account_.CreditRemoval(r.physicalTimeRemovedMs);
    return r;
}

} // namespace TimeReversal
} // namespace Deep2
