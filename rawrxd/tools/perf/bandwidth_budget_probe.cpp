// ============================================================================
// bandwidth_budget_probe.cpp
//
// RAWRXD_PERFECT_DARK_BANDWIDTH_001
//
// Drives BandwidthBudget.hpp with REAL measured inputs and real falsification.
//
// WHERE THE INPUTS COME FROM -- this is the part that must not drift:
//
//   MODEL_BYTES       file size of G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf
//   MEASURED_TPS      Deep2 decode rate observed on this host, CPU route,
//                     DEEP2_DISABLE_VULKAN=1, prompt "The capital of France is",
//                     8 tokens:
//                         [STREAM] RESULT generated=8 promptTokens=5
//                                    decodeMs=23637.1 tps=0.34
//
// MEASURED_TPS is passed in on the command line so the probe recomputes
// nothing the engine already reported. Bandwidth is DERIVED from the two
// measured quantities, and is therefore an OUTPUT of this probe rather than an
// assumption smuggled into it:
//
//     effective_bytes_per_second = MODEL_BYTES * MEASURED_TPS
//
// That is only valid while Deep2 re-reads the whole model every token, which
// is the current policy (no working residency resolver in the tree). The probe
// states that dependency instead of hiding it.
// ============================================================================

#include "perf/BandwidthBudget.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace rawrxd::perf;

namespace {
int g_run = 0, g_fail = 0;
void check(bool ok, const char* what) {
    ++g_run; if (!ok) ++g_fail;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    std::fflush(stdout);
}
double db(const char* s, double d) { return s ? std::atof(s) : d; }
} // namespace

int main(int argc, char** argv) {
    const double modelBytes  = db(argc > 1 ? argv[1] : nullptr, 1363935456.0);
    const double measuredTps = db(argc > 2 ? argv[2] : nullptr, 0.34);
    const double targetTps   = db(argc > 3 ? argv[3] : nullptr, 150.0);

    std::printf("=== RAWRXD_PERFECT_DARK_BANDWIDTH_001 ===\n");
    std::printf("MODEL_BYTES=%.0f\n", modelBytes);
    std::printf("MEASURED_TPS_CPU=%.4f\n", measuredTps);
    std::printf("TARGET_TPS=%.1f\n\n", targetTps);

    // -----------------------------------------------------------------
    // 1. What Deep2 costs RIGHT NOW, derived from two measured quantities.
    // -----------------------------------------------------------------
    // Under the current policy every decode token re-reads the mapped model, so
    // bytes touched per token == model size. That is a POLICY consequence of
    // there being no working residency resolver, and it is stated as such.
    const double bytesPerTokenNow = modelBytes;
    const double effectiveBpsNow = modelBytes * measuredTps;

    std::printf("== A. DEEP2 TODAY (derived from measurement) ==\n");
    std::printf("ACTIVE_BYTES_PER_TOKEN_GB=%.3f\n", bytesPerTokenNow / kGB);
    std::printf("EFFECTIVE_BANDWIDTH_GB_S=%.4f\n", effectiveBpsNow / kGB);
    std::printf("POLICY_WHOLE_MODEL_REREAD=1\n");
    std::printf("BANDWIDTH_MEASURED_HERE=0  (derived, not probed)\n");
    std::printf("TRAFFIC_MEASURED_HERE=1    (from decodeMs/token)\n\n");

    check(bytesPerTokenNow > 0.0, "bytes-per-token is a real quantity");
    check(effectiveBpsNow > 0.0,  "effective bandwidth is derivable from measurement");

    // -----------------------------------------------------------------
    // 2. The reverse-traffic contract, evaluated at the TARGET bandwidth.
    // -----------------------------------------------------------------
    // 1.2 TB/s is the STATED design assumption, not a measurement of this host.
    const double designBandwidth = 1.2 * kTB;

    std::printf("== B. THE REVERSE-TRAFFIC CONTRACT (design bandwidth) ==\n");
    Budget b;
    b.sustainedBandwidthBytesPerSec = designBandwidth;
    b.logicalModelBytes             = modelBytes;
    b.activeBytesPerToken           = 0.0;   // solved for below
    b.targetTps                     = targetTps;
    // Overheads left at zero: they are NOT measured here, and inventing them
    // would place a fabricated numerator beside a measured denominator.
    const Feasibility fZero = evaluate(b);

    std::printf("WEIGHT_BUDGET_PER_TOKEN_GB=%.3f\n",
                fZero.weightBudgetPerToken / kGB);
    std::printf("DESIGN_BANDWIDTH_IS_MEASURED=0\n\n");

    check(std::fabs(fZero.weightBudgetPerToken - 8.0 * kGB) < 0.2 * kGB,
          "1.2 TB/s at 150 TPS yields ~8 GB/token weight budget");

    // The collapse factor actually required: today vs allowed.
    //
    // Routed THROUGH evaluate() rather than computed here. The first version
    // did this arithmetic inline and printed REDUCTION_REQUIRED_PCT=-486.54 --
    // a negative required reduction, because the model already fits the budget
    // so no collapse exists to quantify. Section C was reproducing the very
    // defect the header's regime guard exists to prevent.
    const double allowedBytes = fZero.weightBudgetPerToken;
    {
        Budget today;
        today.sustainedBandwidthBytesPerSec = designBandwidth;
        today.logicalModelBytes   = modelBytes;
        today.activeBytesPerToken = bytesPerTokenNow;
        today.targetTps           = targetTps;
        const Feasibility ft = evaluate(today);

        std::printf("== C. REQUIRED COLLAPSE (measured today vs allowed) ==\n");
        std::printf("REGIME=%s\n", regimeName(ft.regime));
        std::printf("MODEL_FITS_TOKEN_BUDGET=%d\n", ft.modelFitsBudget ? 1 : 0);
        std::printf("COLLAPSE_REQUIRED=%d\n", ft.collapseRequired ? 1 : 0);
        if (ft.collapseRequired) {
            std::printf("COLLAPSE_REQUIRED_X=%.2f\n", ft.collapseFactor);
            std::printf("REDUCTION_REQUIRED_PCT=%.2f\n", ft.reductionRequiredPct);
        } else {
            std::printf("COLLAPSE_REQUIRED_X=NA_NOT_BINDING\n");
            std::printf("REDUCTION_REQUIRED_PCT=NA_NOT_BINDING\n");
        }
        std::printf("BYTES_PER_TOKEN_BUDGET_GB=%.3f\n\n", allowedBytes / kGB);

        // The defect this section previously contained, frozen.
        check(!ft.collapseRequired,
              "C a model that fits the budget reports NO collapse required");
        check(ft.reductionRequiredPct == 0.0,
              "C reduction is 0, never a negative percentage");
    }

    // Logical scope may stay large; physical realization may not.
    std::printf("== D. LOGICAL vs PHYSICAL ==\n");
    std::printf("LOGICAL_MODEL_GB=%.3f\n", modelBytes / kGB);
    std::printf("LOGICAL_MAY_EXCEED_PHYSICAL=%d\n",
                Laws::logicalMayExceedPhysical() ? 1 : 0);
    std::printf("PHYSICAL_MAY_BE_FALSIFIED=%d\n",
                Laws::physicalMayBeFalsified() ? 1 : 0);
    std::printf("MODEL_SIZE_IS_NOT_THE_CONSTRAINT=1\n\n");
    check(Laws::logicalMayExceedPhysical() && !Laws::physicalMayBeFalsified(),
          "D logical may exceed physical; physical may never be falsified");

    // -----------------------------------------------------------------
    // 3. Falsification: the ceiling must be able to FAIL.
    // -----------------------------------------------------------------
    std::printf("== E. FALSIFICATION ==\n");
    {
        // Overheads that alone exceed the bandwidth at the target rate.
        // A ceiling computed from raw bandwidth would report this as FEASIBLE.
        Budget bad;
        bad.sustainedBandwidthBytesPerSec = designBandwidth;
        bad.logicalModelBytes  = modelBytes;
        bad.activeBytesPerToken= 1.0 * kGB;
        bad.targetTps          = targetTps;
        bad.kvBytesPerToken    = 9.0 * kGB;   // > the 8 GB budget by itself
        const Feasibility fb = evaluate(bad);
        std::printf("E1 weight_budget_GB=%.3f tps_ceiling=%.2f reachable=%d\n",
                    fb.weightBudgetPerToken / kGB, fb.tpsCeiling,
                    fb.targetReachable ? 1 : 0);
        check(!fb.targetReachable,
              "E1 overheads exceeding the budget make the target UNREACHABLE");
        check(fb.tpsCeiling == 0.0,
              "E1 ceiling collapses to 0 rather than clamping to feasible");

        // Zero bandwidth must not produce an infinite ceiling.
        Budget zero;
        zero.sustainedBandwidthBytesPerSec = 0.0;
        zero.activeBytesPerToken = 1.0 * kGB;
        zero.targetTps = targetTps;
        const Feasibility fz = evaluate(zero);
        check(fz.tpsCeiling == 0.0 && !fz.targetReachable,
              "E2 zero bandwidth yields 0 TPS, not infinity");

        // A realistic realized size clears the target.
        Budget good;
        good.sustainedBandwidthBytesPerSec = designBandwidth;
        // Logical scope must EXCEED the realization for this case to mean
        // anything. Using the 1.36 GB model here made the logical scope
        // SMALLER than the 4 GB realization -- the same category error as the
        // -486% case, and the assertion caught it.
        good.logicalModelBytes  = 400.0 * kGB;   // 400 GB logical scope
        good.activeBytesPerToken= 4.0 * kGB;     // 4 GB realized per token
        good.targetTps          = targetTps;
        const Feasibility fg = evaluate(good);
        std::printf("E3 logical=400GB active=4GB tps_ceiling=%.1f headroom=%.2f "
                    "regime=%s\n",
                    fg.tpsCeiling, fg.headroomVsTarget, regimeName(fg.regime));
        check(fg.targetReachable,
              "E3 a 4 GB/token realization is reachable at 150 TPS");
        check(fg.logicalToPhysicalRatio > 1.0,
              "E3 logical scope exceeds physical realization");
        check(!fg.modelFitsBudget,
              "E3 a 400 GB model does NOT fit the per-token budget");
        check(fg.regime == Regime::TargetMet,
              "E3 regime reads TARGET_MET when the ceiling clears the goal");
        check(std::fabs(fg.tpsCeiling - 300.0) < 1.0,
              "E3 4 GB/token yields the ~300 TPS bandwidth ceiling");

        // E5 REGRESSION: the modelled-denominator defect, frozen.
        //
        // The first version of this probe fed a 1.36 GB model into a budget
        // derived for a 400 GB model and printed:
        //
        //     COLLAPSE_REQUIRED_X   = 0.170
        //     REDUCTION_REQUIRED_PCT = -486.54
        //
        // A negative "required reduction" is not a small number; it is proof
        // that the collapse figure was computed in a regime where it has no
        // meaning. The model already fits the budget, so no collapse exists.
        //
        // This case asserts the guard, so the defect cannot return silently as
        // a plausible-looking negative percentage.
        {
            Budget reg;
            reg.sustainedBandwidthBytesPerSec = designBandwidth;
            reg.logicalModelBytes   = modelBytes;    // 1.36 GB: FITS the budget
            reg.activeBytesPerToken = modelBytes;    // whole-model reread today
            reg.targetTps           = targetTps;
            const Feasibility fr = evaluate(reg);

            std::printf("E5 regime=%s fits_budget=%d collapse_required=%d "
                        "factor=%s pct=%s\n",
                        regimeName(fr.regime), fr.modelFitsBudget ? 1 : 0,
                        fr.collapseRequired ? 1 : 0,
                        fr.collapseRequired ? "NUMBER" : "NA",
                        fr.collapseRequired ? "NUMBER" : "NA");

            check(fr.modelFitsBudget,
                  "E5 a 1.36 GB model FITS the 8 GB/token budget");
            check(!fr.collapseRequired,
                  "E5 no collapse is reported where none is required");
            check(fr.reductionRequiredPct == 0.0,
                  "E5 reduction is 0, never a negative percentage");
            check(fr.regime != Regime::BandwidthBound,
                  "E5 regime is not BANDWIDTH_BOUND for a model that fits");
            check(fr.regime == Regime::ComputeBound || fr.regime == Regime::TargetMet,
                  "E5 regime correctly reads COMPUTE_BOUND or TARGET_MET");

            // And the binding constraint is named, not left to inference.
            std::printf("E5 BINDING_CONSTRAINT=%s\n",
                        fr.regime == Regime::BandwidthBound ? "BANDWIDTH"
                                                            : "COMPUTE_OR_OVERHEAD");
            check(fr.regime != Regime::BandwidthBound,
                  "E5 binding constraint is NOT bandwidth at this model size");
        }

        // -----------------------------------------------------------------
        // F. POSITIVE CONTROLS -- valid extremes that MUST be ACCEPTED.
        //
        // A guard that only rejects nonsense has not learned to distinguish
        // nonsense from correctness; it has learned "reject unusual". These two
        // cases were previously mis-classified as suspect because one is a
        // ceiling and the other is a budget. Both are dimensionally valid,
        // reproducible, and load-bearing.
        //
        //   "theoretical ceiling" != "not real"
        //
        // If these ever start being rejected as nonsense, the classifier has
        // regressed into magnitude-detection.
        // -----------------------------------------------------------------
        std::printf("== F. POSITIVE CONTROLS (VALID_EXTREME, EXPECT_ACCEPT) ==\n");
        {
            // F1: 1.2 TB/s / 150 TPS = 8 GB/token.
            const NumberVerdict v1 = classifyBudget(fZero.weightBudgetPerToken, false);
            std::printf("F1 8GB_per_token cls=%s expect_accept=%d reason=%s\n",
                        v1.cls == NumberClass::ValidExtreme ? "VALID" : "INVALID",
                        v1.expectAccept ? 1 : 0, v1.reason.c_str());
            check(v1.cls == NumberClass::ValidExtreme,
                  "F1 8 GB/token budget is VALID_EXTREME, not nonsense");
            check(v1.expectAccept,
                  "F1 the guard ACCEPTS a large-but-correct budget");

            // F2: 1.2 TB/s / 4 GB per token = 300 TPS ceiling.
            Budget c;
            c.sustainedBandwidthBytesPerSec = designBandwidth;
            c.logicalModelBytes   = 400.0 * kGB;
            c.activeBytesPerToken = 4.0 * kGB;
            c.targetTps           = targetTps;
            const Feasibility fc = evaluate(c);
            const NumberVerdict v2 = classifyCeiling(fc.tpsCeiling, designBandwidth > 0.0);
            std::printf("F2 ceiling_300tps cls=%s expect_accept=%d reason=%s\n",
                        v2.cls == NumberClass::ValidExtreme ? "VALID" : "INVALID",
                        v2.expectAccept ? 1 : 0, v2.reason.c_str());
            check(std::fabs(fc.tpsCeiling - 300.0) < 1.0,
                  "F2 the 300 TPS figure reproduces exactly");
            check(v2.cls == NumberClass::ValidExtreme && v2.expectAccept,
                  "F2 a theoretical CEILING is VALID_EXTREME and is accepted");

            // F3: the invalid extreme from the same family must still be
            // REJECTED, so accepting F1/F2 did not blunt the guard.
            const NumberVerdict v3 = classifyBudget(0.0, true);
            std::printf("F3 collapsed cls=%s expect_accept=%d reason=%s\n",
                        v3.cls == NumberClass::ValidExtreme ? "VALID" : "INVALID",
                        v3.expectAccept ? 1 : 0, v3.reason.c_str());
            check(v3.cls == NumberClass::InvalidExtreme && !v3.expectAccept,
                  "F3 an invalid extreme is still REJECTED alongside the valid ones");

            // F4: NEGATIVE must never be accepted, at ANY magnitude.
            const NumberVerdict v4 = classifyBudget(-1.0, false);
            check(!v4.expectAccept,
                  "F4 a negative budget is rejected regardless of the ceiling");
        }

        // -----------------------------------------------------------------
        // G. TEST-FIXTURE REGRESSION (E3's original bad vector).
        //
        // E3 failed because the FIXTURE paired a 1.36 GB logical scope with a
        // 4 GB realization, violating logical > physical. The correct handling
        // is NOT to weaken the assertion. It is to keep the bad vector as an
        // EXPECT_FAIL and use a corrected vector for the PASS.
        //
        // This is the piece that makes the correction durable: both the mistake
        // and the fix are frozen.
        // -----------------------------------------------------------------
        std::printf("== G. TEST-FIXTURE REGRESSION (EXPECT_FAIL preserved) ==\n");
        {
            // Recorded, not assumed: the expected failure is only meaningful if
            // it is actually observed on the bad vector.
            bool g_badVectorHeldFail = false;
            Budget bad;
            bad.sustainedBandwidthBytesPerSec = designBandwidth;
            bad.logicalModelBytes   = modelBytes;    // 1.36 GB
            bad.activeBytesPerToken = 4.0 * kGB;    // 4 GB  -> logical < physical
            bad.targetTps           = targetTps;
            const Feasibility fb = evaluate(bad);

            const bool assertionHolds = fb.logicalToPhysicalRatio > 1.0;
            g_badVectorHeldFail = !assertionHolds;   // EXPECT_FAIL proven

            std::printf("G1 bad_vector logical<physical ratio=%.3f "
                        "assertion_holds=%d EXPECTED=FAIL PROVEN_FAIL=%d\n",
                        fb.logicalToPhysicalRatio, assertionHolds ? 1 : 0,
                        g_badVectorHeldFail ? 1 : 0);

            check(fb.logicalToPhysicalRatio < 1.0,
                  "G1 the bad vector is preserved and still violates the invariant");
            check(!(fb.logicalToPhysicalRatio > 1.0),
                  "G1 the ORIGINAL assertion FAILS on the bad vector "
                  "(assertion was NOT weakened)");
            check(g_badVectorHeldFail, "G1 EXPECTED_FAIL is proven, not assumed");
        }
    }   // end section E

    std::printf("\nCHECKS_RUN=%d CHECKS_FAIL=%d\n", g_run, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}