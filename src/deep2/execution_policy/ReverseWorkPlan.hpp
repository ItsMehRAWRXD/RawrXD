// ============================================================================
// ReverseWorkPlan.hpp — AVAILABLE_TIME → WORK_BUDGET → execute|reuse|skip|…
//
// MODEL_SIZE ≠ WORK_REQUIRED → ΔWORK = presented − required (opportunity)
// Fail-closed: Unknown/MustVerify → Execute; UserLocked → never altered.
// ============================================================================
#pragma once

#include "DifferenceEngine.hpp"
#include "ExecutionObservation.hpp"
#include "ExecutionPolicy.hpp"
#include "LearnedProfile.hpp"
#include "RealtimeKernel.hpp"
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

enum class WorkProofState : uint8_t {
    Unknown = 0,   // → MustExecute
    MustVerify,    // → Execute / verify
    ReuseSafe,     // → candidate avoidance
    VerifiedSkip,  // → skip allowed
    UserLocked     // → never altered
};

enum class WorkDisposition : uint8_t {
    Execute = 0,
    Reuse,
    VerifiedSkip,
    Stream,
    Recompute,
    MustExecute
};

struct WorkSignature {
    uint64_t regionId = 0;
    uint32_t layer = 0;
    WorkClass cls = WorkClass::Other;
    uint64_t hash = 0;
};

struct WorkBudgetIntent {
    double targetTokenMs = 0.0;
    double targetTps = 0.0;
    uint64_t maxVramBytes = 0;
    uint64_t maxRamBytes = 0;
    bool allowReuse = true;
    bool allowVerifiedSkip = true;
    bool allowRecompute = true;
    bool allowStreaming = true;
};

struct WorkPlanEntry {
    WorkSignature work;
    WorkDisposition disposition = WorkDisposition::MustExecute;
    WorkProofState proofState = WorkProofState::Unknown;
    double predictedCostUs = 0.0;
    double predictedSavedUs = 0.0;
    uint64_t proofId = 0;
    bool userLocked = false;
};

struct ReverseWorkPlan {
    double wallBudgetUs = 0.0;
    double predictedWallUs = 0.0;
    double predictedSpeedup = 1.0;

    uint64_t workPresented = 0;
    uint64_t workExecuted = 0;
    uint64_t workAvoided = 0;

    ExecutionGap workGap; // ΔWORK opportunity
    std::vector<WorkPlanEntry> entries;
    std::string detail;
};

inline WorkDisposition DispositionFromProof(WorkProofState s,
                                            const WorkBudgetIntent& intent) {
    switch (s) {
    case WorkProofState::UserLocked:
        return WorkDisposition::MustExecute;
    case WorkProofState::ReuseSafe:
        return intent.allowReuse ? WorkDisposition::Reuse
                                 : WorkDisposition::Execute;
    case WorkProofState::VerifiedSkip:
        return intent.allowVerifiedSkip ? WorkDisposition::VerifiedSkip
                                        : WorkDisposition::Execute;
    case WorkProofState::MustVerify:
        return WorkDisposition::Execute;
    case WorkProofState::Unknown:
    default:
        return WorkDisposition::MustExecute; // fail-closed
    }
}

inline double WallBudgetUsFromIntent(const WorkBudgetIntent& intent) {
    if (intent.targetTokenMs > 0.0)
        return intent.targetTokenMs * 1000.0;
    if (intent.targetTps > 0.0)
        return 1.0e6 / intent.targetTps;
    return 0.0;
}

// Census region costs are caller-supplied; proof states from invalidation map.
struct WorkRegionObservation {
    WorkSignature work;
    WorkProofState proof = WorkProofState::Unknown;
    double measuredCostUs = 0.0;
    bool userLocked = false;
};

inline ReverseWorkPlan ReverseWorkPlanFromIntent(
    const WorkBudgetIntent& intent,
    const std::vector<WorkRegionObservation>& regions,
    double baselineWallUs,
    const ExecutionPolicy* /*policyLocks*/ = nullptr,
    const LearnedProfile* /*learned*/ = nullptr) {
    ReverseWorkPlan plan;
    plan.wallBudgetUs = WallBudgetUsFromIntent(intent);
    plan.workPresented = regions.size();

    double execUs = 0.0;
    double savedUs = 0.0;
    double verifyTaxUs = 0.0;

    for (const auto& r : regions) {
        WorkPlanEntry e;
        e.work = r.work;
        e.proofState = r.userLocked ? WorkProofState::UserLocked : r.proof;
        e.userLocked = r.userLocked;
        e.predictedCostUs = r.measuredCostUs;
        e.disposition = DispositionFromProof(e.proofState, intent);

        if (e.disposition == WorkDisposition::Reuse ||
            e.disposition == WorkDisposition::VerifiedSkip) {
            e.predictedSavedUs = r.measuredCostUs;
            savedUs += r.measuredCostUs;
            // light verifier tax on avoidance
            verifyTaxUs += r.measuredCostUs * 0.05;
            ++plan.workAvoided;
        } else if (e.disposition == WorkDisposition::Stream &&
                   intent.allowStreaming) {
            e.predictedSavedUs = r.measuredCostUs * 0.3;
            savedUs += e.predictedSavedUs;
            execUs += r.measuredCostUs - e.predictedSavedUs;
            ++plan.workExecuted;
        } else {
            execUs += r.measuredCostUs;
            ++plan.workExecuted;
        }
        plan.entries.push_back(e);
    }

    const double netSaved = savedUs - verifyTaxUs;
    plan.predictedWallUs =
        baselineWallUs > 0.0 ? (baselineWallUs - netSaved) : execUs + verifyTaxUs;
    if (plan.predictedWallUs < 0.0)
        plan.predictedWallUs = 0.0;
    plan.predictedSpeedup =
        ComputeRealSpeedup(baselineWallUs, plan.predictedWallUs);

    plan.workGap =
        WorkOpportunityGap(plan.workPresented, plan.workExecuted);
    // Prefer time-budget gap when intent has a wall target.
    if (plan.wallBudgetUs > 0.0 && baselineWallUs > 0.0) {
        plan.workGap = LatencyGap(plan.wallBudgetUs / 1000.0,
                                  baselineWallUs / 1000.0);
        plan.workGap.type = GapClass::Work;
    }

    plan.detail = "presented=" + std::to_string(plan.workPresented) +
                  " executed=" + std::to_string(plan.workExecuted) +
                  " avoided=" + std::to_string(plan.workAvoided) +
                  " predWallUs=" + std::to_string(plan.predictedWallUs);
    return plan;
}

// Live Unstatic work map line for IDE / telemetry.
inline std::string FormatUnstaticWorkMap(const ReverseWorkPlan& p) {
    char buf[512];
    const double avoidedPct =
        p.workPresented > 0
            ? (100.0 * (double)p.workAvoided / (double)p.workPresented)
            : 0.0;
    std::snprintf(
        buf, sizeof(buf),
        "UNSTATIC WORK MAP  presented=%llu executed=%llu avoided=%llu (%.1f%%)  "
        "predSpeedup=%.3fx  wallBudgetUs=%.0f predWallUs=%.0f  Δ=%s",
        (unsigned long long)p.workPresented,
        (unsigned long long)p.workExecuted,
        (unsigned long long)p.workAvoided, avoidedPct, p.predictedSpeedup,
        p.wallBudgetUs, p.predictedWallUs, p.workGap.detail.c_str());
    return buf;
}

} // namespace Exec
} // namespace Deep2
