// ============================================================================
// EvolutionState.hpp — continual Unstatic promotion frontier
// Each accepted patch becomes the next baseline. Experiments may fail;
// accepted performance is monotonic: best₀ ≤ best₁ ≤ best₂ …
// ============================================================================
#pragma once

#include "PhysicalWorkCensus.hpp"
#include "SpeedupAttribution.hpp"
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

enum class CandidateVerdict : uint8_t {
    Reject = 0,   // slower, unequal output, or gate fail
    Hold,         // equal — do not promote
    Rollback,     // applied then proven slower / incorrect
    Promote       // becomes new baseline
};

struct EvolutionState {
    PhysicalWorkCensus baseline;
    double cumulativeSpeedup = 1.0;
    uint64_t generation = 0;
    double bestWallUs = 0.0; // accepted frontier (lower is better)
    bool authorityPreserved = true;
    std::string lastNote;

    void seed(const PhysicalWorkCensus& b0) {
        baseline = b0;
        cumulativeSpeedup = 1.0;
        generation = 0;
        bestWallUs = b0.wallUs;
        authorityPreserved = true;
        lastNote = "seeded";
    }

    // NEW_BASELINE only if OUTPUT_EQUIVALENT && NET_TIME_SAVED>0
    // && REAL_SPEEDUP>1 && AUTHORITY=PRESERVED
    CandidateVerdict tryPromote(const PhysicalWorkCensus& candidate,
                                bool outputEquivalent,
                                bool authorityOk = true) {
        if (!authorityOk) {
            authorityPreserved = false;
            lastNote = "AUTHORITY_NOT_PRESERVED";
            return CandidateVerdict::Reject;
        }
        const PhysicalWorkDelta d = DiffCensus(baseline, candidate);
        const AttributionGateResult g =
            EvaluateAttributionGate(baseline, candidate, d, outputEquivalent);

        if (!outputEquivalent) {
            lastNote = "OUTPUT_NOT_EQUIVALENT";
            return CandidateVerdict::Reject;
        }
        // Equal wall → hold (no promote)
        if (candidate.wallUs > 0.0 && baseline.wallUs > 0.0 &&
            candidate.wallUs == baseline.wallUs) {
            lastNote = "EQUAL_WALL_HOLD";
            return CandidateVerdict::Hold;
        }
        if (candidate.wallUs > baseline.wallUs) {
            lastNote = "CANDIDATE_SLOWER";
            return CandidateVerdict::Reject;
        }
        if (!g.pass || !g.promotionEvidence) {
            lastNote = g.firstFalse.empty() ? "GATE_FAIL" : g.firstFalse;
            return CandidateVerdict::Reject;
        }

        // Promote: candidate becomes baseline₁
        const double local = d.realSpeedup > 1.0 ? d.realSpeedup : 1.0;
        cumulativeSpeedup *= local;
        ++generation;
        baseline = candidate;
        if (bestWallUs <= 0.0 || candidate.wallUs < bestWallUs)
            bestWallUs = candidate.wallUs;
        lastNote = FormatAttributionExplain(d);
        return CandidateVerdict::Promote;
    }

    // After an applied patch proves worse — restore prior census.
    CandidateVerdict rollback(const PhysicalWorkCensus& priorBaseline) {
        baseline = priorBaseline;
        lastNote = "ROLLBACK";
        return CandidateVerdict::Rollback;
    }
};

// Monotonic accepted frontier: each Promote must not increase bestWallUs.
inline bool FrontierMonotonic(double prevBestWallUs, double newBestWallUs) {
    if (prevBestWallUs <= 0.0) return newBestWallUs > 0.0;
    return newBestWallUs > 0.0 && newBestWallUs <= prevBestWallUs;
}

struct EvolutionStepRecord {
    uint64_t generation = 0;
    CandidateVerdict verdict = CandidateVerdict::Reject;
    double localSpeedup = 1.0;
    double cumulativeSpeedup = 1.0;
    double bestWallUs = 0.0;
    std::string note;
};

// Drive one discovery generation against current baseline.
inline EvolutionStepRecord StepEvolution(EvolutionState& evo,
                                         const PhysicalWorkCensus& candidate,
                                         bool outputEquivalent,
                                         bool authorityOk = true) {
    EvolutionStepRecord rec;
    rec.generation = evo.generation;
    const double prevBest = evo.bestWallUs;
    const double prevCum = evo.cumulativeSpeedup;
    const auto prior = evo.baseline;

    rec.verdict = evo.tryPromote(candidate, outputEquivalent, authorityOk);
    rec.cumulativeSpeedup = evo.cumulativeSpeedup;
    rec.bestWallUs = evo.bestWallUs;
    rec.note = evo.lastNote;

    if (rec.verdict == CandidateVerdict::Promote) {
        rec.localSpeedup =
            (prevCum > 0.0) ? (evo.cumulativeSpeedup / prevCum) : 1.0;
        if (!FrontierMonotonic(prevBest, evo.bestWallUs)) {
            // Should be impossible if tryPromote is correct — fail closed.
            evo.rollback(prior);
            evo.cumulativeSpeedup = prevCum;
            --evo.generation;
            rec.verdict = CandidateVerdict::Rollback;
            rec.note = "FRONTIER_MONOTONICITY_VIOLATION";
            rec.cumulativeSpeedup = evo.cumulativeSpeedup;
            rec.bestWallUs = evo.bestWallUs;
            rec.localSpeedup = 1.0;
        }
    } else {
        rec.localSpeedup = 1.0;
    }
    return rec;
}

} // namespace Exec
} // namespace Deep2
