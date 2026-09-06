// time_reversal_smoke.cpp — debt → thrust → loss manifest → hotpatch
#include "time_reversal/AsymmetricThrust.hpp"
#include "time_reversal/PhysicalHotpatchEngine.hpp"
#include "time_reversal/TpsLossManifest.hpp"
#include "time_reversal/TpsLossManifestJson.hpp"
#include <cmath>
#include <cstdio>

using namespace Deep2::TimeReversal;

static int fail(const char* m) {
    std::printf("FAIL %s\n", m);
    return 1;
}

int main() {
    const double curMs = 28.20;
    const double tgtMs = 20.00;
    auto debt = MakeDebt(curMs, tgtMs);
    if (std::fabs(debt.debtMs - 8.20) > 1e-6) return fail("TOKEN_DEBT");
    if (std::fabs(debt.debtRatio - (8.20 / 28.20)) > 1e-4) return fail("DEBT_RATIO");

    // Hotpatch score dimensional form
    const double recoverable = 14.80;
    const double conf = 0.85;
    const double score = (debt.debtMs / curMs) * recoverable * conf;
    if (score <= 0.0) return fail("HOTPATCH_SCORE");

    // Predicted net: 8.70 gross - 0.35 overhead = 8.35 >= 8.20
    const double net = 8.70 - 0.35;
    auto req = MakeHotpatchRequirement(curMs, tgtMs, net, 0.0, 0.0);
    if (!req.predictedPass) return fail("PHYSICAL_HOTPATCH_BUDGET");

    // Debt consume loop: 8.20 → 5.60 → 2.10 → 0
    double d = 8.20;
    const double steps[] = {25.60, 22.10, 19.85};
    for (double after : steps) {
        d = MakeDebt(after, tgtMs).debtMs;
    }
    if (d > 1e-9) return fail("DEBT_NOT_CONSUMED");

    // Asymmetric thrust: do not add power
    auto asym = BuildAsymmetryMap(96.0, 38.0, 5600.0, 4100.0, 2700.0);
    if (asym.powerDeficit) return fail("NO_POWER_DEFICIT_DEFAULT");
    if (!asym.thrustAsymmetry) return fail("THRUST_ASYMMETRY");
    auto press = MakeThrustPressure(8.20, 4.10, 11.0);
    if (std::fabs(press.hotpatchPressure - 45.1) > 0.2) return fail("PRESSURE_11X");

    LossLane lanes[] = {
        {"FFN", 1.40, 1.10, true, true, true, {"runtime_counter", "FFN_US", 4096, 47, {}}},
        {"NVME", 1.15, 0.95, true, true, true, {"runtime_counter", "WEIGHT_WAIT_NVME_US", 4096, 47, {}}},
        {"WORK_AVOIDANCE", 1.50, 1.35, true, true, true, {"runtime_counter", "REUSE_SKIP_US", 2048, 47, {}}},
        {"DMA", 0.70, 0.55, true, true, true, {"runtime_counter", "DMA_WAIT_US", 2048, 47, {}}},
        {"MULTI_GPU", 0.65, 0.55, true, true, true, {"runtime_counter", "GPU_SYNC_US", 2048, 47, {}}},
        {"SCHEDULER_SYNC", 0.55, 0.45, true, true, true, {"runtime_counter", "SCHED_US", 2048, 47, {}}},
        {"KV", 0.55, 0.40, true, true, true, {"runtime_counter", "KV_US", 2048, 47, {}}},
        {"VRAM", 0.60, 0.50, true, true, true, {"runtime_counter", "VRAM_STAGE_US", 2048, 47, {}}},
        {"ATTENTION", 0.35, 0.20, true, true, true, {"runtime_counter", "ATTN_US", 2048, 47, {}}},
        {"COMPUTE", 0.40, 0.15, true, true, true, {"runtime_counter", "MISC_US", 2048, 47, {}}},
        {"RAM", 0.35, 0.20, true, true, true, {"runtime_counter", "RAM_STAGE_US", 2048, 47, {}}},
    };
    // Sum lanes = 8.20 exactly for bound check; no silent unattributed pad
    HotpatchCandidate patches[] = {
        {"reuse_safe_skip", ThrustPatchKind::DragRemoval, 1.35, {"redundant_ffn", 0.90}},
        {"gpu1_hot_residency", ThrustPatchKind::Side, 2.15, {"thrust_asymmetry", 0.94}},
        {"prefetch_horizon", ThrustPatchKind::Anticipatory, 0.92, {"late_weight_prefetch", 0.91}},
        {"kv_layout", ThrustPatchKind::DragRemoval, 0.61, {"kv_pressure", 0.88}},
    };

    auto man = BuildTpsLossManifest(35.46, 50.0, lanes, 11, 0.0, asym, patches, 4);
    if (!CriticalPathLossBound(man, 0.05)) return fail("LOSS_SUM_BOUND");
    if (man.ranks[0].id == nullptr) return fail("RANK");
    // 11x must not inflate physical debt
    if (man.tokenTimeDebtMs > 8.21) return fail("NO_11X_ON_PHYSICAL");

    auto json = EmitTpsLossManifestJson(man);
    std::printf("%s\n", FormatTpsLossManifest(man).c_str());

    PhysicalHotpatchEngine eng;
    eng.SetTargetTps(50.0);
    eng.SetClassifiedBudget(13.4, 3.4, 6.1, 5.3);
    auto measured = eng.ApplyMeasuredPatch(
        47, 48, 28.20, 19.85, 0.35, true, true, 28200.0, 19850.0);
    if (!measured.physicalHotpatchPass) return fail("PHYSICAL_HOTPATCH_001");
    if (std::fabs(measured.physicalTimeRemovedMs - 8.35) > 1e-6)
        return fail("PHYSICAL_TIME_REMOVED");
    if (measured.measuredTps < 50.0) return fail("TARGET_TPS");

    // Write example manifest beside evidence when possible
    FILE* f = std::fopen("screenpilot-tps-loss-manifest.json", "wb");
    if (f) {
        std::fwrite(json.data(), 1, json.size(), f);
        std::fclose(f);
    }

    std::printf("%s\n", FormatHotpatch(measured).c_str());
    std::printf("P1_TPS_LOSS_MANIFEST_001 / PHYSICAL_HOTPATCH_001 smoke PASS\n");
    return 0;
}
