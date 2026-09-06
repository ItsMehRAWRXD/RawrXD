// TimeReversalEngine.cpp — closed-loop observe → plan → promote façade
#include "TimeReversalEngine.hpp"
#include <cstdio>

namespace Deep2 {
namespace TimeReversal {

TimeReversalEngine::TimeReversalEngine(EngineConfig cfg) : cfg_(cfg) {
    targetTps_ = cfg.defaultTargetTps;
}

void TimeReversalEngine::SetTargetTps(double tps) { targetTps_ = tps; }

void TimeReversalEngine::ObserveGeneration(
    uint64_t nowMs, const PerfGenerationRecord& g,
    const TokenTimeLedger& meanTokenLedger,
    uint64_t workPresented, uint64_t workExecuted, uint64_t workAvoided) {
    if (havePrevLedger_) {
        lastDisappear_ = CompareLedgers(prevLedger_, meanTokenLedger);
    }
    prevLedger_ = meanTokenLedger;
    havePrevLedger_ = true;
    lastLedger_ = meanTokenLedger;
    lastGen_ = g;
    haveGen_ = true;
    tracker_.RecordGeneration(nowMs, g, workPresented, workExecuted, workAvoided);
}

void TimeReversalEngine::SetResourceSnapshot(const ResourceSnapshot& rs) {
    resources_ = rs;
}

PerfWindows TimeReversalEngine::Windows(uint64_t nowMs) const {
    return tracker_.Snapshot(nowMs);
}

ResourceOpportunity TimeReversalEngine::Opportunity() const {
    return DeriveResourceOpportunity(resources_);
}

ReverseTargetPlan TimeReversalEngine::PlanRemovals(
    const RemovalCandidate* cands, int n) const {
    const double ms = haveGen_ ? MsPerTokenFromTps(lastGen_.decodeTps)
                               : (lastLedger_.totalUs / 1000.0);
    const double tgt = targetTps_ > 0.0 ? targetTps_ : lastGen_.decodeTps;
    return SolveReverseTarget(ms, tgt, cands, n);
}

SustainedDriftReport TimeReversalEngine::Drift(uint64_t nowMs) const {
    return AnalyzeSustainedDrift(Windows(nowMs));
}

bool TimeReversalEngine::LastLedgerReconciled(double* absErrUs) const {
    return LedgerReconciles(lastLedger_, cfg_.ledgerReconcileTolUs, absErrUs);
}

PerfPromotionRecord TimeReversalEngine::BuildPromotionDraft(
    uint64_t baselineGen, uint64_t candidateGen,
    const Hash256& baselineSha, const Hash256& candidateSha,
    const Hash256& policySha, const Hash256& authoritySha,
    const Hash256& rulesetSha, bool outputEquivalent) const {
    PerfPromotionRecord r;
    r.baselineGeneration = baselineGen;
    r.candidateGeneration = candidateGen;
    r.baselineStateSha = baselineSha;
    r.candidateStateSha = candidateSha;
    r.policySha = policySha;
    r.authoritySha = authoritySha;
    r.rulesetSha = rulesetSha;
    r.outputEquivalent = outputEquivalent;
    const auto w = Windows(0);
    r.baselineMedianTps = w.session.medianTps;
    r.candidateMedianTps = lastGen_.decodeTps;
    r.baselineP95MsToken = w.session.p95MsPerToken;
    r.candidateP95MsToken = MsPerTokenFromTps(lastGen_.decodeTps);
    r.realSpeedup = lastDisappear_.realSpeedup;
    r.disappearedMsPerToken = lastDisappear_.disappearedUs / 1000.0;
    r.measurementDurationMs = static_cast<uint64_t>(w.session.wallMs);
    r.measuredTokens = w.session.tokens;
    const auto gates = EvaluatePromotionGates(
        r, cfg_.promoteMinDurationMs, cfg_.promoteMinTokens,
        true, true, true, true);
    r.sustained = w.last30m.medianTps > 0.0 &&
                  w.last30m.p05Tps >= w.last30m.medianTps * 0.85;
    r.promotable = gates.allPass() && r.sustained;
    return r;
}

std::string TimeReversalEngine::FormatDashboard(uint64_t nowMs) const {
    const auto w = Windows(nowMs);
    const double curTps = haveGen_ ? lastGen_.decodeTps : w.last10s.medianTps;
    const double curMs = MsPerTokenFromTps(curTps);
    const double tgt = targetTps_;
    const double tgtMs = MsPerTokenFromTps(tgt);
    const double must = (tgt > 0.0) ? (std::max)(0.0, curMs - tgtMs) : 0.0;
    const auto opp = Opportunity();
    char buf[2048];
    std::snprintf(buf, sizeof(buf),
        "┌────────── RAWRXD TIME REVERSAL ──────────┐\n"
        " CURRENT  %.1f TPS   %.2f ms/token   TTFT %.0f ms\n"
        " TARGET   %.1f TPS   %.2f ms/token\n"
        " MUST DISAPPEAR  %.2f ms/token\n"
        " LAST 30 MIN  median %.1f  p05 %.1f  p95 %.1f\n"
        " RECOVERABLE ~%.2f ms/token  (%s)\n"
        " LEDGER_OK=%s\n"
        "└───────────────────────────────────────────┘\n",
        curTps, curMs, haveGen_ ? lastGen_.ttftMs : 0.0,
        tgt, tgtMs, must,
        w.last30m.medianTps, w.last30m.p05Tps, w.last30m.p95Tps,
        opp.estimatedRecoverableUsPerToken / 1000.0, opp.note,
        LastLedgerReconciled() ? "YES" : "NO");
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
