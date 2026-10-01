// PerfPolicy.hpp — RAWRXD_PERF_POLICY_SCHEMA_001
//
// SCHEMA ONLY. This header declares types. It contains no logic, no selection,
// no measurement, and no behaviour of any kind. Nothing includes it yet, so
// adding it cannot change routing, throughput, or any receipt.
//
// It exists to fix the *shape* of the requested-TPS policy before any of it is
// implemented, so that the contract can be reviewed independently of the
// selector that will eventually satisfy it.
//
// The governing invariant, restated here because it is the reason this file is
// deliberately inert:
//
//     TPS cannot create correctness authority.
//
// A candidate that is fast and uncertified is not "probably better" than a
// certified slower candidate. It is uncertified, and ranking must never see it.
//
// ---------------------------------------------------------------------------
// Authority dependency chain
// ---------------------------------------------------------------------------
//
//     REFERENCE ORACLE                 PRESENT  RealGGUFParity (RAWRXD_REAL_GGUF_
//                                               PARITY_001), golden + CPU reference,
//                                               bound to model SHA-256 and byte count.
//     NUMERICAL COMPARATOR/CERTIFICATE PRESENT  RealGGUFParity::Thresholds /
//                                               StepMetrics, --verify-golden.
//     CANDIDATE ADMISSION              NOT IMPLEMENTED (below)
//     TPS RANKING                      NOT IMPLEMENTED
//
// Two authorities are deliberately kept separate and must never be collapsed:
//
//     RealExecution != NumericalCorrectness
//
// A forward can be genuinely GPU-resident, perfectly accounted, finite, and
// still compute the wrong logits. Execution-reality predicates prove what ran;
// only the oracle-backed numerical certificate proves what it computed.
//
// Note on determinism: `Deep2Engine::isDeterministicGreedy()` reports that a
// configuration *intends* deterministic decoding. That is metadata and must
// never satisfy MEASURED_DETERMINISM, which requires reproducing the same
// result across repeat executions from an equivalent starting state.

#ifndef RAWRXD_PERF_POLICY_HPP
#define RAWRXD_PERF_POLICY_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2::Perf {

// ===========================================================================
// Input: what the caller wants and what it will not accept compromised.
// ===========================================================================
struct PerfPolicy {
    // Optimization target, never an override. A candidate that meets every
    // admission gate but misses this is reported as TARGET_MET=0 with the best
    // certified figure, not adjusted into a pass.
    double minDecodeTps = 0.0;

    // Hard requirements. Any one of these rejecting a candidate rejects it
    // regardless of throughput.
    bool requireCorrectness      = true;
    bool requireDeterminism      = true;
    bool requireForwardAccounting = true;
    bool requireCapacity         = true;
    bool requireResidencyPolicy  = true;
    bool requireNoStall          = true;

    // Resource ceiling. Bounds candidate generation so a selector can never
    // propose a regime the caller has forbidden.
    unsigned maxWorkers = 0;   // 0 = no caller-imposed ceiling
};

// ===========================================================================
// Candidate description: an immutable description of one possible regime.
// NOT a selection. Nothing constructs these yet.
// ===========================================================================
struct ExecutionCandidate {
    std::string id;                       // stable identifier, e.g. "gpu0-resident-packed-v1"

    // Geometry the candidate was derived for. Used as the regime key so a
    // candidate is never reused across a geometry it was not derived for.
    std::uint32_t hidden        = 0;
    std::uint32_t intermediate  = 0;
    std::uint32_t layers        = 0;
    std::uint32_t heads         = 0;
    std::uint32_t kvHeads       = 0;
    std::uint32_t context       = 0;
    std::uint64_t modelBytes    = 0;
    std::uint64_t residentBytes = 0;
    std::string   weightType;             // GGUF type name
    std::uint32_t gpuCount      = 0;

    // Execution dimensions. Only dimensions Deep2 genuinely exposes may appear
    // here; absent dimensions stay false rather than being invented to populate
    // the design.
    bool   packedQuant     = false;
    bool   nativeQuant     = false;
    bool   fusedQkv        = false;
    bool   fusedAttention  = false;
    bool   prefetch        = false;
    bool   dualGpu         = false;
    std::uint32_t gpu0Share = 0;
    std::uint32_t gpu1Share = 0;
    std::uint32_t attentionWorkers = 1;
    std::uint32_t mlpWorkers       = 1;
};

// ===========================================================================
// Admission: six independent authorities, AND-combined.
//
//   Admit(C) = R(C) & A(C) & N(C) & D(C) & K(C) & V(C)
//
// Each is reported separately and never collapsed, so a rejection names which
// authority refused rather than collapsing into an opaque "correctness: fail".
// A field that was never evaluated is UNKNOWN, and UNKNOWN rejects. Absence of
// evidence is not evidence of absence.
// ===========================================================================
enum class Predicate {
    UNKNOWN = 0,   // never evaluated -> rejects
    PASS    = 1,
    FAIL    = 2,
};

enum class Authority {
    EXECUTION_REALITY   = 0,   // R: the claimed forward actually happened
    FORWARD_ACCOUNTING  = 1,   // A: materialization conservation holds
    NUMERICAL_CORRECT   = 2,   // N: oracle-backed logits/tokens match
    MEASURED_DETERMINISM= 3,   // D: repeat execution reproduced, not a config flag
    CAPACITY_FEASIBLE   = 4,   // K: fits installed VRAM/RAM/GPU topology
    RESIDENCY_FALLBACK  = 5,   // V: residency + zero-unplanned-fallback policy
    COUNT               = 6,
};

const char* authorityName(Authority a) {
    switch (a) {
        case Authority::EXECUTION_REALITY:    return "EXECUTION_REALITY";
        case Authority::FORWARD_ACCOUNTING:   return "FORWARD_ACCOUNTING";
        case Authority::NUMERICAL_CORRECT:    return "NUMERICAL_CORRECT";
        case Authority::MEASURED_DETERMINISM: return "MEASURED_DETERMINISM";
        case Authority::CAPACITY_FEASIBLE:    return "CAPACITY_FEASIBLE";
        case Authority::RESIDENCY_FALLBACK:   return "RESIDENCY_FALLBACK";
        case Authority::COUNT:                break;
    }
    return "UNKNOWN";
}

struct AdmissionResult {
    // One predicate per Authority. All must be PASS for the candidate to be
    // admitted. A single FAIL rejects; any UNKNOWN also rejects.
    Predicate verdicts[static_cast<int>(Authority::COUNT)] = {
        Predicate::UNKNOWN, Predicate::UNKNOWN, Predicate::UNKNOWN,
        Predicate::UNKNOWN, Predicate::UNKNOWN, Predicate::UNKNOWN,
    };

    // Measured real production decode throughput. Populated only for an admitted
    // candidate, and only from real decode — never from a synthetic or
    // microkernel measurement.
    double measuredDecodeTps = 0.0;
    bool   measuredFromRealDecode = false;

    // First authority that refused, or Authority::COUNT when none did.
    Authority rejectedBy = Authority::COUNT;
    const char* rejectReason = "";

    const char* rejectedByName() const { return authorityName(rejectedBy); }
};

// Defined inline rather than in a companion .cpp on purpose: this header was
// authored without definitions so it could not affect behaviour, which left it
// unusable — any inclusion would fail to link on these two symbols. Inline
// definitions keep the file inert (no selection, no I/O, no state) while making
// it self-contained.
inline bool AdmissionResult::admitted() const {
    for (int i = 0; i < static_cast<int>(Authority::COUNT); ++i) {
        // UNKNOWN rejects exactly as FAIL does. Absence of evaluation is not
        // evidence of correctness.
        if (verdicts[i] != Predicate::PASS) return false;
    }
    // A candidate can never be admitted on a throughput figure that did not come
    // from real decode, regardless of what its predicates say.
    return measuredFromRealDecode;
}

// ===========================================================================
// Outcome: what the policy reports when nothing reaches the target.
// ===========================================================================
//
//   REQUESTED_TPS=30
//   BEST_CERTIFIED_TPS=21.7
//   TARGET_MET=0
//   BEST_CERTIFIED_REGIME=<id>
//
// No threshold manipulation turns TARGET_MET=0 into a pass. When no candidate
// is admitted at all, BEST_CERTIFIED_TPS is reported as unmeasured rather than
// as zero, because zero is a throughput measurement and the situation is an
// absence of candidates.
struct PolicyOutcome {
    double requestedTps      = 0.0;
    double bestCertifiedTps  = 0.0;
    bool   bestCertifiedMeasured = false;
    bool   targetMet         = false;
    std::string bestRegimeId;
    std::uint32_t candidatesGenerated = 0;
    std::uint32_t candidatesAdmitted  = 0;
};

// ===========================================================================
// Status
// ===========================================================================
//
// Everything in this header is unimplemented. This enumeration exists so that
// no consumer can mistake the presence of these types for a working selector.
enum class SchemaStatus {
    NOT_IMPLEMENTED = 0,
};

inline constexpr SchemaStatus kPerfPolicyStatus = SchemaStatus::NOT_IMPLEMENTED;

} // namespace Deep2::Perf

#endif // RAWRXD_PERF_POLICY_HPP
