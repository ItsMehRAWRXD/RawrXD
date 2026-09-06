// ============================================================================
// SpeedupAttribution.hpp — reverse-engineered REAL_SPEEDUP (physical causes)
//
// Authority:
//   REAL_SPEEDUP = baselineWallUs / candidateWallUs
//   REAL_SPEEDUP > 1  ⇔  candidateWallUs < baselineWallUs
//
// WORK_AVOIDED > 0 is NOT sufficient. Require NET_TIME_SAVED > 0.
// HexMag / Unstatic optimize net wall contribution, not TPS theater.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>

namespace Deep2 {
namespace Exec {

// Orthogonal classes — never conflate. Promotion is explicit only:
//   discover → applicability → verify → reproduce → generalize
//   → measure work avoided → NET_TIME_SAVED > 0 → REAL_SPEEDUP > 1
//   → preserve weights/authority → explicit promotion
// Research must not wash out a failed product gate (e.g. P1_UI_ENCODING_002).
enum class HexMagDiscoveryClass : uint8_t {
    KnownOptimization = 0,  // predefined transformation
    TunedConfiguration,     // known knobs, better values
    RuntimeDiscovery,       // new execution rule discovered empirically
    CertifiedHotpatch       // discovery passed verify + persistence gates
};

// R0..R10 ladder fields (microseconds; wall fields are EXTERNAL authority).
struct SpeedupAttribution {
    // R0 / R9 — external wall (authority)
    double baselineWallUs = 0.0;
    double candidateWallUs = 0.0;

    // R1..R3 — work accounting
    uint64_t workPresented = 0;
    uint64_t workExecuted = 0;
    uint64_t workAvoided = 0; // presented - executed (units are work ops)

    // Avoided cost terms (positive = time that no longer happens)
    double computeAvoidedUs = 0.0;
    double memoryStallAvoidedUs = 0.0;
    double ioAvoidedUs = 0.0;
    double migrationAvoidedUs = 0.0;

    // New overhead terms (positive = time added by avoidance machinery)
    double verifierCostUs = 0.0;      // R4
    double discoveryCostUs = 0.0;     // R7 discovery
    double patchCostUs = 0.0;         // R7 hotpatch / dispatch
    double synchronizationCostUs = 0.0;

    // R8 — net
    double netAvoidedUs = 0.0;

    // R10
    double realSpeedup = 0.0;

    HexMagDiscoveryClass discoveryClass = HexMagDiscoveryClass::KnownOptimization;
    std::string note;
};

inline double ComputeNetAvoidedUs(const SpeedupAttribution& a) {
    return a.computeAvoidedUs + a.memoryStallAvoidedUs + a.ioAvoidedUs +
           a.migrationAvoidedUs - a.verifierCostUs - a.discoveryCostUs -
           a.patchCostUs - a.synchronizationCostUs;
}

inline double ComputeRealSpeedup(double baselineWallUs, double candidateWallUs) {
    if (baselineWallUs <= 0.0 || candidateWallUs <= 0.0)
        return 0.0;
    return baselineWallUs / candidateWallUs;
}

inline void FinalizeAttribution(SpeedupAttribution& a) {
    a.netAvoidedUs = ComputeNetAvoidedUs(a);
    a.realSpeedup =
        ComputeRealSpeedup(a.baselineWallUs, a.candidateWallUs);
}

struct SpeedupGateResult {
    bool outputEquivalent = false;
    bool correctnessGate = false;
    bool netAvoidedPositive = false;     // netAvoidedUs > 0
    bool candidateFasterThanBaseline = false; // candidateWall < baselineWall
    bool realSpeedupGt1 = false;
    bool pass = false;
    std::string firstFalse;
};

// Fail-closed promotion gate for any HexMag / Unstatic candidate.
inline SpeedupGateResult EvaluateSpeedupGate(const SpeedupAttribution& a,
                                             bool outputEquivalent,
                                             bool correctnessGate) {
    SpeedupGateResult g;
    g.outputEquivalent = outputEquivalent;
    g.correctnessGate = correctnessGate;
    g.netAvoidedPositive = (a.netAvoidedUs > 0.0);
    g.candidateFasterThanBaseline =
        (a.baselineWallUs > 0.0 && a.candidateWallUs > 0.0 &&
         a.candidateWallUs < a.baselineWallUs);
    g.realSpeedupGt1 = (a.realSpeedup > 1.0);

    auto fail = [&](const char* pred) {
        if (g.firstFalse.empty())
            g.firstFalse = pred;
    };
    if (!g.outputEquivalent) fail("OUTPUT_EQUIVALENT");
    if (!g.correctnessGate) fail("CORRECTNESS_GATE");
    if (!g.netAvoidedPositive) fail("NET_AVOIDED_US");
    if (!g.candidateFasterThanBaseline) fail("CANDIDATE_WALL_US");
    if (!g.realSpeedupGt1) fail("REAL_SPEEDUP");

    g.pass = g.outputEquivalent && g.correctnessGate && g.netAvoidedPositive &&
             g.candidateFasterThanBaseline && g.realSpeedupGt1;
    return g;
}

// Candidate wall decomposition (diagnostic; does not replace external wall).
struct CandidateWallBreakdown {
    double usefulComputeUs = 0.0;
    double redundantComputeUs = 0.0;
    double verifyUs = 0.0;
    double memoryStallUs = 0.0;
    double h2dUs = 0.0;
    double nvmeIoUs = 0.0;
    double migrationUs = 0.0;
    double synchronizationUs = 0.0;
    double patchOverheadUs = 0.0;
    double discoveryOverheadUs = 0.0;

    double sum() const {
        return usefulComputeUs + redundantComputeUs + verifyUs + memoryStallUs +
               h2dUs + nvmeIoUs + migrationUs + synchronizationUs +
               patchOverheadUs + discoveryOverheadUs;
    }
};

} // namespace Exec
} // namespace Deep2
