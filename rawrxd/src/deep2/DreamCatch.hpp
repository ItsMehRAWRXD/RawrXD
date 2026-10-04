#pragma once
// ============================================================================
// DreamCatch.hpp — RAWRXD_DREAMCATCH_PREDICTED_CHASERS_001
//
//   DREAM  ->  DREAMCATCH  ->  [COMMIT LINE]  ->  CHASERS  ->  REALITY
//
// DREAM      predicts possible future state. It never executes, never allocates
//            execution memory, never touches weights, KV, or model state.
// DREAMCATCH freezes one prediction, immutably, BEFORE any Chaser runs. Once
//            frozen it cannot be rewritten, which is the whole point: a
//            prediction that can be edited after seeing reality is not a
//            prediction.
// CHASERS   execute for real. They may change reality. They may not change the
//            Dream they are chasing.
//
// The separation that makes this meaningful rather than decorative:
//
//     DREAM_EXECUTES        = 0
//     DREAMCATCH_EXECUTES   = 0
//     CHASER_EXECUTES       = 1
//     CHASER_CAN_MUTATE_DREAM = 0
//     PREDICTION_REWRITE_AFTER_CATCH = 0
//
// Strength comes from MULTIPLE chasers. One realization matching Dream could be
// coincidence. Eight different realizations converging on the same endpoint is
// evidence that the endpoint was predicted rather than discovered.
// ============================================================================

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
namespace dream {

// ---------------------------------------------------------------------------
// Immutable snapshot of reality at the moment of dreaming. Facts only.
// Deliberately contains NO pointer and NO address: Dream reads a description of
// the world, never a handle into it.
// ---------------------------------------------------------------------------
struct StateSnapshot {
    std::uint64_t originEpoch = 0;

    // residency description
    std::uint64_t residentBytes = 0;
    std::uint64_t deviceBytes  = 0;
    std::uint64_t hostMappedBytes = 0;

    // capability description
    bool     avx512 = false;
    bool     avx2   = false;
    bool     gpuPresent = false;
    std::uint32_t deviceCount = 0;

    // shape description
    std::uint64_t tokensResident = 0;
    std::uint64_t kvBytes        = 0;

    bool operator==(const StateSnapshot&) const noexcept = default;
};

// ---------------------------------------------------------------------------
// What must become true. This is what Dream reasons backwards from.
// ---------------------------------------------------------------------------
struct EndpointContract {
    enum class Kind : std::uint8_t {
        FINITE_OUTPUT = 0,
        KERNEL_READY  = 1,
        GPU_RESIDENT  = 2,
        HOST_MAPPED   = 3,
        CORRECTNESS_WITHIN_BOUND = 4,
        ADMISSION_GRANTED = 5,
    };
    Kind kind = Kind::FINITE_OUTPUT;
    double errorBound = 0.0;
    std::uint32_t rows = 0, cols = 0;
    std::uint32_t quantType = 0;

    bool operator==(const EndpointContract&) const noexcept = default;
};

const char* endpointKindName(EndpointContract::Kind k);

// ---------------------------------------------------------------------------
// The predicted future.
// ---------------------------------------------------------------------------
struct PredictedState {
    EndpointContract endpoint;
    // What Dream believes reality will look like when the endpoint is reached.
    std::uint64_t predictedResidentBytes = 0;
    std::uint32_t predictedDeviceCount  = 0;
    bool          predictedGpuResident   = false;
};

// ---------------------------------------------------------------------------
// DreamCatch: an immutable, hashed prediction.
//
// The frozen fields cannot be assigned after freeze(). The mutable ones are
// bookkeeping only (chaser bookkeeping, timestamps) and are excluded from the
// content hash.
// ---------------------------------------------------------------------------
class DreamCatch {
public:
    DreamCatch() = default;

    // Construct and freeze. There is no way to build an unfrozen catch.
    static DreamCatch freeze(StateSnapshot origin,
                             PredictedState predicted,
                             std::uint64_t dreamId);

    // ---- frozen, content-addressed ----
    std::uint64_t dreamId()      const noexcept { return dreamId_; }
    const StateSnapshot&    origin()    const noexcept { return origin_; }
    const PredictedState&   predicted() const noexcept { return predicted_; }
    const EndpointContract& endpoint()  const noexcept { return predicted_.endpoint; }
    std::uint64_t originEpoch()       const noexcept { return origin_.originEpoch; }
    std::uint64_t predictedHash()     const noexcept { return predictedHash_; }
    std::uint64_t originHash()        const noexcept { return originHash_; }
    bool isFrozen() const noexcept { return frozen_; }

    // Attempt to rewrite a frozen prediction. Always refused. Returns false and
    // changes nothing, so a caller cannot smuggle a retrofit past the boundary.
    bool tryRewrite(const PredictedState& replacement) const;

    // ---- bookkeeping, excluded from the content hash ----
    void noteChaser(std::uint64_t chaserId);
    std::uint32_t chaserCount() const noexcept { return (std::uint32_t)chasers_.size(); }

private:
    bool frozen_ = false;
    std::uint64_t dreamId_ = 0;
    StateSnapshot origin_;
    PredictedState predicted_;
    std::uint64_t originHash_ = 0;
    std::uint64_t predictedHash_ = 0;
    std::vector<std::uint64_t> chasers_;
};

std::uint64_t hashSnapshot(const StateSnapshot& s);
std::uint64_t hashPredicted(const PredictedState& p);

// ---------------------------------------------------------------------------
// How far reality landed from the prediction.
// ---------------------------------------------------------------------------
struct StateDistance {
    int  residencyDelta = 0;
    int  deviceDelta    = 0;
    int  endpointKindDelta = 0;
    int  residencyBandDelta = 0;   // coarse band, not exact bytes

    int total() const noexcept {
        return residencyDelta + deviceDelta + endpointKindDelta + residencyBandDelta;
    }
};

StateDistance measureDistance(const DreamCatch& c, const StateSnapshot& actual,
                              EndpointContract::Kind actualEndpoint);

enum class ChaseResult : std::uint8_t {
    CAUGHT = 0,     // distance 0 and endpoint matched
    NEAR = 1,       // endpoint matched, state differed
    DIVERGED = 2,   // endpoint kind differed
    LOST = 3,       // nothing materialised
};

const char* chaseResultName(ChaseResult r);

ChaseResult classify(const StateDistance& d);

// ---------------------------------------------------------------------------
// Chaser: the real side. Executes. Records evidence against a FROZEN catch.
// ---------------------------------------------------------------------------
struct ChaserEvidence {
    std::uint64_t dreamId = 0;
    std::uint64_t chaserId = 0;
    std::string  realization;      // e.g. "CPU_GENERIC", "GPU_HOST_GEMV"

    StateSnapshot startState;
    StateSnapshot endState;
    EndpointContract::Kind actualEndpoint = EndpointContract::Kind::ADMISSION_GRANTED;

    std::uint64_t executionNs = 0;
    bool          correct = false;
    double        maxError = 0.0;

    StateDistance distance;
    ChaseResult   result = ChaseResult::LOST;

    // Did reality match what was frozen BEFORE this ran?
    bool endpointReached = false;
    bool dreamHashUnchanged = false;
};

class ChaserRegistry {
public:
    static ChaserRegistry& Instance();

    // Submit evidence for a frozen catch. The registry verifies the catch was
    // not modified, and refuses evidence whose recorded dream hash disagrees.
    bool submit(const DreamCatch& frozen, ChaserEvidence e);

    struct Summary {
        std::uint64_t dreamId = 0;
        std::uint32_t chases = 0;
        std::uint32_t reached = 0;
        std::uint32_t diverged = 0;
        std::uint32_t lost = 0;
        std::uint32_t tampered = 0;      // evidence claiming a changed dream
        ChaseResult consensus = ChaseResult::LOST;
        std::uint32_t consensusAgreement = 0;   // how many agreed
    };
    Summary summarise(std::uint64_t dreamId) const;

    std::size_t count() const;
    void clear();

private:
    ChaserRegistry() = default;
    std::vector<ChaserEvidence> evidence_;
};

} // namespace dream
} // namespace Deep2