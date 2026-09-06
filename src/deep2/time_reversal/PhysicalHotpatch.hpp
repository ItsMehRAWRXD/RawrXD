// PhysicalHotpatch.hpp — time debt → physical hotpatch requirement
#pragma once
#include "RemovalPortfolio.hpp"
#include "TimeClassBudget.hpp"
#include "TimeDebtAccount.hpp"
#include "TimeReversalTypes.hpp"
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

struct PhysicalHotpatchRequirement {
    TimeDebtSnapshot debt{};
    double hotpatchOverheadMs = 0.0;
    double safetyMarginMs = 0.0;
    double physicalRecoveryRequiredMs = 0.0; // debt + overhead + margin
    bool predictedPass = false;
    double predictedNetRemovedMs = 0.0;
};

inline PhysicalHotpatchRequirement MakeHotpatchRequirement(
    double currentMs, double targetMs,
    double predictedNetRemovedMs,
    double hotpatchOverheadMs = 0.0,
    double safetyMarginMs = 0.0) {
    PhysicalHotpatchRequirement r;
    r.debt = MakeDebt(currentMs, targetMs);
    r.hotpatchOverheadMs = hotpatchOverheadMs;
    r.safetyMarginMs = safetyMarginMs;
    r.physicalRecoveryRequiredMs =
        r.debt.debtMs + hotpatchOverheadMs + safetyMarginMs;
    r.predictedNetRemovedMs = predictedNetRemovedMs;
    r.predictedPass = predictedNetRemovedMs + 1e-9 >= r.physicalRecoveryRequiredMs;
    return r;
}

struct PhysicalHotpatchGate {
    bool timeDebtBeforeGt0 = false;
    bool measuredTimeRemovedGt0 = false;
    bool patchOverheadAccounted = false;
    bool criticalPathReduced = false;
    bool outputEquivalent = false;
    bool authorityUnchanged = false;
    bool timeDebtAfterLtBefore = false;

    bool allPass() const {
        return timeDebtBeforeGt0 && measuredTimeRemovedGt0 &&
               patchOverheadAccounted && criticalPathReduced &&
               outputEquivalent && authorityUnchanged &&
               timeDebtAfterLtBefore;
    }
};

struct PhysicalHotpatchResult {
    uint64_t generationBefore = 0;
    uint64_t generationAfter = 0;
    double beforeMs = 0.0;
    double afterMs = 0.0;
    double timeDebtBefore = 0.0;
    double timeDebtAfter = 0.0;
    double physicalTimeRemovedMs = 0.0;
    double measuredTps = 0.0;
    double targetTps = 0.0;
    PhysicalHotpatchGate gates{};
    bool physicalHotpatchPass = false;
};

inline PhysicalHotpatchResult MeasureHotpatch(
    uint64_t genBefore, uint64_t genAfter,
    double beforeMs, double afterMs, double targetMs,
    double patchOverheadMsAccounted,
    bool outputEquivalent, bool authorityUnchanged,
    double criticalPathBeforeUs, double criticalPathAfterUs) {
    PhysicalHotpatchResult r;
    r.generationBefore = genBefore;
    r.generationAfter = genAfter;
    r.beforeMs = beforeMs;
    r.afterMs = afterMs;
    r.timeDebtBefore = MakeDebt(beforeMs, targetMs).debtMs;
    r.timeDebtAfter = MakeDebt(afterMs, targetMs).debtMs;
    r.physicalTimeRemovedMs = beforeMs - afterMs;
    r.measuredTps = TpsFromMsPerToken(afterMs);
    r.targetTps = TpsFromMsPerToken(targetMs);
    r.gates.timeDebtBeforeGt0 = r.timeDebtBefore > 0.0;
    r.gates.measuredTimeRemovedGt0 = r.physicalTimeRemovedMs > 0.0;
    r.gates.patchOverheadAccounted = patchOverheadMsAccounted >= 0.0;
    r.gates.criticalPathReduced = criticalPathAfterUs < criticalPathBeforeUs;
    r.gates.outputEquivalent = outputEquivalent;
    r.gates.authorityUnchanged = authorityUnchanged;
    r.gates.timeDebtAfterLtBefore = r.timeDebtAfter < r.timeDebtBefore;
    r.physicalHotpatchPass = r.gates.allPass();
    return r;
}

inline std::string FormatHotpatch(const PhysicalHotpatchResult& r) {
    char buf[640];
    std::snprintf(buf, sizeof(buf),
        "PHYSICAL_HOTPATCH_001\n"
        "BEFORE=%.2f AFTER=%.2f REMOVED=%.2f\n"
        "DEBT %0.2f → %0.2f   TPS=%.2f (target %.2f)\n"
        "GATES debt>0=%d removed>0=%d overhead=%d cpath=%d "
        "equiv=%d auth=%d debt↓=%d → %s\n",
        r.beforeMs, r.afterMs, r.physicalTimeRemovedMs,
        r.timeDebtBefore, r.timeDebtAfter, r.measuredTps, r.targetTps,
        (int)r.gates.timeDebtBeforeGt0, (int)r.gates.measuredTimeRemovedGt0,
        (int)r.gates.patchOverheadAccounted, (int)r.gates.criticalPathReduced,
        (int)r.gates.outputEquivalent, (int)r.gates.authorityUnchanged,
        (int)r.gates.timeDebtAfterLtBefore,
        r.physicalHotpatchPass ? "PASS" : "FAIL");
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
