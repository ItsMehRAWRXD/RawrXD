// ============================================================================
// BandwidthBudget.hpp
//
// RAWRXD_PERFECT_DARK_BANDWIDTH_001
//
// Turns "how low can EFFECTIVE_FRESH_BYTES_PER_TOKEN go?" from a slogan into a
// computed quantity with a falsifiable denominator.
//
// THE GOVERNING RELATIONSHIP
//
//     TPS_ceiling  ~=  sustained_execution_bandwidth
//                    -------------------------------
//                    effective_fresh_bytes_per_token
//
// At 150 TPS with ~1.2 TB/s, the budget for fresh weight traffic is:
//
//     1.2e12 / 150  ~=  8.0e9 bytes  ~=  8 GB per token
//
// Everything else (KV traffic, activations, attention, sync, reconstruction
// cost) is spent OUT OF that budget, so 8 GB is a CEILING, not a target.
//
// THE REVERSAL
//
//     LOGICAL_MODEL_SCOPE_PER_TOKEN  >=  8 GB   (may be unbounded)
//     PHYSICAL_FRESH_BYTES_PER_TOKEN <=  8 GB   (hard budget)
//
// A 400 GB logical model is not the problem. Re-reading 400 GB every token is.
// So the axis that decides feasibility is physical realization per token, not
// logical model size.
//
// WHAT THIS FILE DELIBERATELY DOES NOT CLAIM
//
//   * It does NOT measure hardware bandwidth. Bandwidth is an INPUT here, and a
//     wrong input yields a confidently wrong ceiling. That measurement belongs
//     to a separate gate that must state its method and its uncertainty.
//
//   * It does NOT measure Deep2's real bytes/token today. It reports the
//     CURRENT policy value, which for the monolithic mmap path is the whole
//     model per token -- and that is a POLICY fact about Deep2, not a
//     measurement of its traffic.
//
// The separation matters: mixing a measured numerator with a modelled
// denominator is how a projection becomes a result.
//
// THE REVERSE-TRADE-TITAN LAW, ENCODED
//
//   LOGICAL_CAPACITY_MAY_EXCEED_PHYSICAL = 1
//   PHYSICAL_CAPACITY_MAY_BE_FALSIFIED  = 0
//   48 GB may be exposed as 96 GB logical; 48 GB may never be REPORTED as 96.
//
// ============================================================================

#ifndef RAWRXD_PERFECT_DARK_BANDWIDTH_HPP
#define RAWRXD_PERFECT_DARK_BANDWIDTH_HPP

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace rawrxd::perf {

// 1 GB = 1e9 bytes (decimal, matching how storage vendors quote model sizes).
inline constexpr double kGB = 1.0e9;
inline constexpr double kTB = 1.0e12;

struct Budget {
    double sustainedBandwidthBytesPerSec = 0.0;  // INPUT, not measured here
    double logicalModelBytes             = 0.0;  // may exceed the budget
    double activeBytesPerToken           = 0.0;  // the whole point
    double targetTps                     = 0.0;

    // Overheads that consume the same budget and therefore must be subtracted
    // before any weight traffic is afforded. Modelled as explicit inputs so a
    // caller cannot quietly assume they are zero.
    double kvBytesPerToken               = 0.0;
    double activationBytesPerToken       = 0.0;
    double reconstructionBytesPerToken   = 0.0;
    double syncBytesPerToken             = 0.0;
};

enum class Regime {
    Undetermined,   // an input is missing or nonsensical
    BandwidthBound, // active bytes/token exceed the budget: collapse REQUIRED
    ComputeBound,   // active FITS the budget but throughput is below target
    TargetMet       // ceiling clears the target with the current realization
};

struct Feasibility {
    double overheadBytesPerToken = 0.0;
    double weightBudgetPerToken  = 0.0;   // budget left after overheads
    double tpsCeiling            = 0.0;   // bandwidth-limited ceiling
    double headroomVsTarget      = 0.0;   // ceiling / targetTps
    bool   targetReachable       = false;

    // The reversal, as an inequality rather than a slogan.
    double logicalToPhysicalRatio = 0.0;

    // ---- REGIME GUARD -------------------------------------------------
    //
    // Added after the instrument produced a physically impossible result.
    //
    // Feeding a 1.36 GB model through a budget derived for a 400 GB model
    // yielded COLLAPSE_REQUIRED_X=0.170 and REDUCTION_REQUIRED_PCT=-486.54.
    // A negative "required reduction" is not a small number, it is a category
    // error: the model already FITS the budget, so no collapse exists to
    // report, and the ratio was computed across a regime where it means
    // nothing.
    //
    // So the collapse is now REPORTED ONLY WHERE IT BINDS. Outside that regime
    // the fields are pinned to a defined "no collapse required" value instead
    // of being allowed to print a negative percentage.
    Regime   regime             = Regime::Undetermined;
    bool     collapseRequired   = false;
    double   collapseFactor     = 1.0;   // meaningful ONLY when required
    double   reductionRequiredPct = 0.0;  // meaningful ONLY when required
    // True when the logical model already fits the per-token budget, which is
    // exactly the case the first version mishandled.
    bool     modelFitsBudget    = false;
};

inline const char* regimeName(Regime r) {
    switch (r) {
        case Regime::Undetermined:  return "UNDETERMINED";
        case Regime::BandwidthBound:return "BANDWIDTH_BOUND";
        case Regime::ComputeBound:  return "COMPUTE_BOUND";
        case Regime::TargetMet:     return "TARGET_MET";
    }
    return "?";
}

// DERIVED. Nothing below is settable.
//
// The ceiling is computed from the BUDGET left after overheads, not from the
// raw bandwidth, because paying 1.2 TB/s of KV traffic against a weight budget
// is a real failure mode that a bandwidth-only calculation hides.
inline Feasibility evaluate(const Budget& b) {
    Feasibility f;

    f.overheadBytesPerToken =
        b.kvBytesPerToken + b.activationBytesPerToken +
        b.reconstructionBytesPerToken + b.syncBytesPerToken;

    if (b.sustainedBandwidthBytesPerSec <= 0.0) {
        f.tpsCeiling = 0.0;
        f.targetReachable = false;
        return f;
    }
    if (b.targetTps <= 0.0) {
        f.tpsCeiling = 0.0;
        f.targetReachable = false;
        return f;
    }

    // Weight budget is whatever bandwidth remains after overheads, expressed
    // per token.
    f.weightBudgetPerToken =
        (b.sustainedBandwidthBytesPerSec / b.targetTps) - f.overheadBytesPerToken;

    if (f.weightBudgetPerToken < 0.0) {
        // Overheads alone exceed the bandwidth at the requested rate. This is a
        // FAILURE, not a rounding artifact, and must not be clamped to zero and
        // then reported as "feasible".
        f.weightBudgetPerToken = 0.0;
        f.tpsCeiling = 0.0;
        f.targetReachable = false;
        return f;
    }

    if (b.activeBytesPerToken > 0.0) {
        f.tpsCeiling = b.sustainedBandwidthBytesPerSec /
                       (f.overheadBytesPerToken + b.activeBytesPerToken);
    } else {
        f.tpsCeiling = 0.0;
    }
    f.headroomVsTarget = b.targetTps > 0.0 ? f.tpsCeiling / b.targetTps : 0.0;

    // ---- REGIME CLASSIFICATION -----------------------------------------
    //
    // Two INDEPENDENT questions were originally conflated into one enum:
    //
    //   (a) is bandwidth the BINDING constraint?   -> regime
    //   (b) must logical scope be collapsed?       -> collapseRequired
    //
    // A 400 GB logical scope realized as 4 GB/token has a 300 TPS ceiling that
    // CLEARS a 150 TPS goal, yet the model does not fit the 8 GB budget. An
    // earlier version reported that as COMPUTE_BOUND, which reads as "bandwidth
    // is not the problem, go faster elsewhere" -- the opposite of the truth.
    // The budget is a COLLAPSE question; the ceiling is a BINDING question.
    f.modelFitsBudget =
        (b.logicalModelBytes > 0.0) && (b.logicalModelBytes <= f.weightBudgetPerToken);

    const bool ceilingClearsTarget = (f.tpsCeiling >= b.targetTps);

    if (!ceilingClearsTarget) {
        // Bandwidth genuinely limits throughput. Distinguish only to say WHY.
        f.regime = (b.activeBytesPerToken > f.weightBudgetPerToken)
                 ? Regime::BandwidthBound     // weight traffic itself is the wall
                 : Regime::ComputeBound;      // weights fit, yet still too slow
    } else {
        f.regime = Regime::TargetMet;
    }

    // The collapse figure is only meaningful where a collapse can exist: when
    // the logical model is genuinely larger than one token may touch.
    // Outside that, reporting it produced a negative "required reduction",
    // which is a category error rather than a measurement.
    if (f.modelFitsBudget) {
        f.collapseRequired     = false;
        f.collapseFactor       = 1.0;
        f.reductionRequiredPct = 0.0;
    } else if (b.activeBytesPerToken > f.weightBudgetPerToken) {
        f.collapseRequired     = true;
        f.collapseFactor       = b.activeBytesPerToken / f.weightBudgetPerToken;
        f.reductionRequiredPct =
            100.0 * (1.0 - f.weightBudgetPerToken / b.activeBytesPerToken);
    } else {
        // Logical exceeds the budget, yet the chosen realization already fits
        // inside it: the reversal is exactly what has been asked for.
        f.collapseRequired     = false;
        f.collapseFactor       = 1.0;
        f.reductionRequiredPct = 0.0;
    }

    // Reachable requires the ceiling to clear the target AND a real
    // per-token realization to exist.
    f.targetReachable = (f.tpsCeiling >= b.targetTps) && (b.activeBytesPerToken > 0.0);
    if (b.logicalModelBytes > 0.0 && b.activeBytesPerToken > 0.0)
        f.logicalToPhysicalRatio = b.logicalModelBytes / b.activeBytesPerToken;
    return f;
}

// The Deep2 state that is TRUE BY INSPECTION of the loader, not by measurement.
//
// loadModel() binds WeightTensor.data straight to GGUFTensor::data and marks
// wt.mapped / wt.hasFileBacking. There is no residency manager with a working
// resolver in the tree, and no eviction, so every decode token re-reads the
// whole mapped model. That is a POLICY consequence of the current code, and
// calling it "measured bandwidth" would be a category error.
inline Budget deep2PolicyToday(double modelBytes, double bandwidthBytesPerSec,
                               double targetTps) {
    Budget b;
    b.sustainedBandwidthBytesPerSec = bandwidthBytesPerSec;
    b.logicalModelBytes             = modelBytes;
    b.activeBytesPerToken           = modelBytes;   // no residency: whole model
    b.targetTps                     = targetTps;
    // Left at zero deliberately: these are not modelled here, and inventing
    // numbers for them would put a fabricated numerator beside a real
    // denominator.
    return b;
}

// ---------------------------------------------------------------------------
// RAWRXD_NONSENSE_NUMBER_REGRESSION_002
//
// A nonsense-number guard that only REJECTS is half a guard. Without positive
// controls it learns "reject weird" rather than "distinguish wrong from right",
// and the next genuinely large-but-correct number gets flattened to something
// more comfortable. That is a classification defect, not a formatting one.
//
// Both classes are therefore first-class:
//
//   INVALID_EXTREME -> EXPECT_REJECT_OR_NA
//   VALID_EXTREME   -> EXPECT_ACCEPT
//
// and these are VALID, which must not be "fixed":
//
//   1.2 TB/s / 150 TPS    =   8 GB/token   (bandwidth-side budget)
//   1.2 TB/s / 4 GB/token  = 300 TPS        (theoretical CEILING)
//
// "Theoretical ceiling" does not mean "not real". It means the number is the
// real result of the DECLARED boundary conditions rather than a measured
// end-to-end runtime result. Both are dimensionally valid, reproducible, and
// load-bearing. A previous version of this file's probe rejected the 300 TPS
// figure on the grounds that it was a ceiling; that was a classification error.
// ---------------------------------------------------------------------------
enum class NumberClass { InvalidExtreme, ValidExtreme };

struct NumberVerdict {
    NumberClass cls = NumberClass::ValidExtreme;
    bool        expectAccept = true;
    std::string reason;
};

// Validates a (budgetBytesPerToken, ceilingTps) pair produced by evaluate().
//
// The rule is INTERNAL CONSISTENCY, not magnitude. A huge number is fine if it
// follows from the inputs; a negative one never is, because a budget and a
// ceiling are non-negative by construction.
inline NumberVerdict classifyBudgetResult(double budgetBytesPerToken,
                                          double tpsCeiling,
                                          bool overheadsExceededBudget) {
    NumberVerdict v;
    if (overheadsExceededBudget) {
        v.cls = NumberClass::InvalidExtreme;
        v.expectAccept = false;
        v.reason = "OVERHEADS_EXCEED_BUDGET_AT_TARGET_RATE";
    } else if (budgetBytesPerToken < 0.0 || tpsCeiling < 0.0) {
        v.cls = NumberClass::InvalidExtreme;
        v.expectAccept = false;
        v.reason = "NEGATIVE_BUDGET_OR_CEILING";
    } else if (budgetBytesPerToken == 0.0 || tpsCeiling == 0.0) {
        v.cls = NumberClass::InvalidExtreme;
        v.expectAccept = false;
        v.reason = "ZERO_FROM_NONPOSITIVE_INPUT";
    } else {
        // Large magnitude is NOT a defect. Reproducibility is what matters.
        v.cls = NumberClass::ValidExtreme;
        v.expectAccept = true;
        v.reason = "DIMENSIONALLY_VALID_AND_REPRODUCIBLE";
    }
    return v;
}

// The budget and the ceiling are INDEPENDENT quantities and are classified
// separately.
//
// This is the same lesson as the Regime fix, applied to the classifier: a
// first version judged the pair together, so a valid 8 GB budget was rejected
// merely because the ceiling happened to be undefined (activeBytesPerToken was
// deliberately left at 0 in that section). One quantity's absence condemned the
// other's correctness. Classify them alone, or neither is trustworthy.
//
// Magnitude is never a defect. A budget of 8 GB and a ceiling of 300 TPS are
// large, surprising, reproducible and dimensionally valid; rejecting either
// because it is big would make the guard a magnitude detector.
inline NumberVerdict classifyBudget(double budgetBytesPerToken,
                                    bool overheadsExceededBudget) {
    NumberVerdict v;
    if (overheadsExceededBudget) {
        v.cls = NumberClass::InvalidExtreme; v.expectAccept = false;
        v.reason = "OVERHEADS_EXCEED_BUDGET_AT_TARGET_RATE";
    } else if (budgetBytesPerToken < 0.0) {
        v.cls = NumberClass::InvalidExtreme; v.expectAccept = false;
        v.reason = "NEGATIVE_BUDGET";
    } else if (budgetBytesPerToken == 0.0) {
        v.cls = NumberClass::InvalidExtreme; v.expectAccept = false;
        v.reason = "ZERO_BUDGET";
    } else {
        v.cls = NumberClass::ValidExtreme; v.expectAccept = true;
        v.reason = "DIMENSIONALLY_VALID_BUDGET";
    }
    return v;
}

inline NumberVerdict classifyCeiling(double tpsCeiling,
                                    bool bandwidthInputPositive) {
    NumberVerdict v;
    if (!bandwidthInputPositive) {
        // Undefined, not invalid: no bandwidth was supplied, so there is no
        // ceiling to judge. Reported as such rather than as a bad number.
        v.cls = NumberClass::ValidExtreme; v.expectAccept = true;
        v.reason = "UNDEFINED_NO_BANDWIDTH_INPUT";
    } else if (tpsCeiling < 0.0) {
        v.cls = NumberClass::InvalidExtreme; v.expectAccept = false;
        v.reason = "NEGATIVE_CEILING";
    } else {
        v.cls = NumberClass::ValidExtreme; v.expectAccept = true;
        v.reason = "DIMENSIONALLY_VALID_CEILING";
    }
    return v;
}

inline std::string render(const char* label, const Budget& b, const Feasibility& f) {
    std::ostringstream o;
    o << "=== " << label << " ===\n";
    o << std::fixed;
    o.precision(3);
    o << "SUSTAINED_BANDWIDTH_GB_S="   << b.sustainedBandwidthBytesPerSec / kGB << "\n";
    o << "LOGICAL_MODEL_GB="           << b.logicalModelBytes / kGB << "\n";
    o << "ACTIVE_BYTES_PER_TOKEN_GB="  << b.activeBytesPerToken / kGB << "\n";
    o << "OVERHEAD_BYTES_PER_TOKEN_GB="<< f.overheadBytesPerToken / kGB << "\n";
    o << "WEIGHT_BUDGET_PER_TOKEN_GB=" << f.weightBudgetPerToken / kGB << "\n";
    o << "TPS_CEILING="                << f.tpsCeiling << "\n";
    o << "TARGET_TPS="                 << b.targetTps << "\n";
    o << "HEADROOM_VS_TARGET="         << f.headroomVsTarget << "\n";
    o << "LOGICAL_TO_PHYSICAL_RATIO="  << f.logicalToPhysicalRatio << "\n";
    o << "REGIME="                     << regimeName(f.regime) << "\n";
    o << "MODEL_FITS_TOKEN_BUDGET="    << (f.modelFitsBudget ? 1 : 0) << "\n";
    o << "COLLAPSE_REQUIRED="          << (f.collapseRequired ? 1 : 0) << "\n";
    // Printed with an explicit N/A when the regime makes it meaningless,
    // rather than as a negative percentage a reader could misread as a result.
    if (f.collapseRequired) {
        o << "COLLAPSE_REQUIRED_X="      << f.collapseFactor << "\n";
        o << "REDUCTION_REQUIRED_PCT="   << f.reductionRequiredPct << "\n";
    } else {
        o << "COLLAPSE_REQUIRED_X=NA_NOT_BINDING\n";
        o << "REDUCTION_REQUIRED_PCT=NA_NOT_BINDING\n";
    }
    o << "TARGET_REACHABLE="           << (f.targetReachable ? 1 : 0) << "\n";
    o << "BANDWIDTH_MEASURED_HERE="    << 0 << "\n";
    o << "TRAFFIC_MEASURED_HERE="      << 0 << "\n";
    return o.str();
}

namespace Laws {
// The reversal, in code.
inline constexpr bool logicalMayExceedPhysical() noexcept { return true; }
inline constexpr bool physicalMayBeFalsified()   noexcept { return false; }
inline constexpr bool ceilingMayIgnoreOverheads() noexcept { return false; }
inline constexpr bool budgetIsMeasuredHere()      noexcept { return false; }
} // namespace Laws

} // namespace rawrxd::perf

#endif // RAWRXD_PERFECT_DARK_BANDWIDTH_HPP