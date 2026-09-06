// TimeReversalEngine.hpp — closed-loop TPS optimizer façade
#pragma once
#include "PerfPromotion.hpp"
#include "PerfWindowTracker.hpp"
#include "ResourceReversal.hpp"
#include "ReverseTargetSolver.hpp"
#include "SustainedDrift.hpp"
#include "TokenTimeLedgerOps.hpp"
#include <vector>

namespace Deep2 {
namespace TimeReversal {

struct EngineConfig {
    double ledgerReconcileTolUs = 250.0; // component sum vs wall
    uint64_t promoteMinDurationMs = 60000;
    uint64_t promoteMinTokens = 512;
    double defaultTargetTps = 0.0; // 0 = unset
};

class TimeReversalEngine {
public:
    explicit TimeReversalEngine(EngineConfig cfg = {});

    void SetTargetTps(double tps);
    double TargetTps() const { return targetTps_; }

    void ObserveGeneration(uint64_t nowMs, const PerfGenerationRecord& g,
                           const TokenTimeLedger& meanTokenLedger,
                           uint64_t workPresented, uint64_t workExecuted,
                           uint64_t workAvoided);

    void SetResourceSnapshot(const ResourceSnapshot& rs);
    PerfWindows Windows(uint64_t nowMs) const;
    ResourceOpportunity Opportunity() const;

    ReverseTargetPlan PlanRemovals(const RemovalCandidate* cands, int n) const;
    DisappearanceReport LastDisappearance() const { return lastDisappear_; }
    SustainedDriftReport Drift(uint64_t nowMs) const;

    bool LastLedgerReconciled(double* absErrUs = nullptr) const;
    PerfPromotionRecord BuildPromotionDraft(
        uint64_t baselineGen, uint64_t candidateGen,
        const Hash256& baselineSha, const Hash256& candidateSha,
        const Hash256& policySha, const Hash256& authoritySha,
        const Hash256& rulesetSha,
        bool outputEquivalent) const;

    std::string FormatDashboard(uint64_t nowMs) const;

private:
    EngineConfig cfg_;
    double targetTps_ = 0.0;
    PerfWindowTracker tracker_;
    ResourceSnapshot resources_{};
    TokenTimeLedger lastLedger_{};
    TokenTimeLedger prevLedger_{};
    bool havePrevLedger_ = false;
    DisappearanceReport lastDisappear_{};
    PerfGenerationRecord lastGen_{};
    bool haveGen_ = false;
};

} // namespace TimeReversal
} // namespace Deep2
