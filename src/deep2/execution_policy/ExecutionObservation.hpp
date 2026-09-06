// ============================================================================
// ExecutionObservation.hpp — INV-4: learn what actually ran, not what was asked
// Invariants: INV-1..INV-10 (see comments at bottom)
// ============================================================================
#pragma once

#include "LearnedProfile.hpp"
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

struct EffectivePlacement {
    std::vector<std::pair<LayerRange, DeviceKind>> layerRanges;
    std::vector<PlacementRule> tensorRules;
    std::vector<std::string> pinnedObserved;
    DeviceKind embeddings = DeviceKind::Host;
    DeviceKind lmHead = DeviceKind::Gpu0;
};

struct ExecutionObservation {
    HardwareSnapshot hardware;
    std::string modelFingerprint;
    std::string modelName;
    std::string quant;

    EffectivePlacement actualPlacement;

    double tokensPerSecond = 0.0;
    double ttftMs = 0.0;

    uint64_t peakVramBytes = 0;
    uint64_t peakRamBytes = 0; // run-local aggregate for legacy consumers

    // Distinct RAM envelopes (run-local vs lifetime)
    uint64_t processWorkingSetCurrent = 0;
    uint64_t runWorkingSetPeak = 0;
    uint64_t processLifetimeWorkingSetPeak = 0; // OS PeakWorkingSetSize — NOT for learning
    uint64_t runPrivateCommitPeak = 0;
    uint64_t modelResidentRam = 0;
    uint64_t marsManagedRam = 0;
    uint64_t streamingWorkingEstimate = 0;

    uint64_t bytesHostToGpu = 0;
    uint64_t bytesNvmeToRam = 0; // = physical read (for legacy)
    uint64_t nvmeLogicalRequestedBytes = 0;
    uint64_t nvmePhysicalReadBytes = 0;
    uint64_t nvmeUsefulPayloadBytes = 0;
    uint64_t nvmePrefetchBytes = 0;
    uint64_t nvmeDiscardedPrefetchBytes = 0;
    uint64_t streamChurnBytes = 0;

    uint32_t migrations = 0;
    uint32_t residencyMisses = 0;
    uint32_t spillToRam = 0;
    uint32_t spillToNvme = 0;

    bool completed = false;
    bool outputValid = false;
    bool fromLiveTelemetry = false;
};

struct ObservationValidation {
    bool ok = false;
    std::string detail; // PROFILE_NOT_FOUND / INCOMPLETE / ...
};

// INV-3: only completed + valid runs may improve profiles.
inline ObservationValidation ValidateObservation(const ExecutionObservation& o) {
    ObservationValidation v;
    if (!o.completed) {
        v.detail = "INCOMPLETE";
        return v;
    }
    if (!o.outputValid) {
        v.detail = "OUTPUT_INVALID";
        return v;
    }
    if (o.modelFingerprint.empty()) {
        v.detail = "PROFILE_NOT_FOUND"; // missing model fp ≡ no profile bind
        return v;
    }
    if (o.hardware.fingerprint.empty() && o.hardware.gpus.empty()) {
        v.detail = "PROFILE_NOT_FOUND";
        return v;
    }
    if (o.tokensPerSecond <= 0.0) {
        v.detail = "NO_THROUGHPUT";
        return v;
    }
    v.ok = true;
    v.detail = "OK";
    return v;
}

// INV-4: policy learned from observed residency, not requested plan.
inline ExecutionPolicy PolicyFromObservation(const ExecutionPolicy& seed,
                                             const ExecutionObservation& o) {
    ExecutionPolicy p = seed;
    const bool haveActual =
        !o.actualPlacement.layerRanges.empty() ||
        !o.actualPlacement.tensorRules.empty();
    if (!haveActual)
        return p; // metrics-only — never synthesize placement (INV-4)

    p.placement.layerRanges = o.actualPlacement.layerRanges;
    if (!o.actualPlacement.tensorRules.empty())
        p.placement.rules = o.actualPlacement.tensorRules;
    if (!o.actualPlacement.pinnedObserved.empty())
        p.placement.pinned = o.actualPlacement.pinnedObserved;

    p.placement.embeddings.force(o.actualPlacement.embeddings,
                                 SettingAuthority::RuntimeLearned,
                                 SettingMutability::TokenBoundary);
    p.placement.lmHead.force(o.actualPlacement.lmHead,
                             SettingAuthority::RuntimeLearned,
                             SettingMutability::TokenBoundary);
    return p;
}

/*
INV-1  Learned profile MUST NOT mutate UserLocked cells.
INV-2  Fingerprint mismatch ≡ PROFILE_NOT_FOUND (no closest-match).
INV-3  Failed/aborted generation MUST NOT improve the profile.
INV-4  recordSuccess placement = actual execution, not requested plan.
INV-5  AutoPlanFromLearned may seed only unlocked fields.
INV-6  Tuner Suggest is advisory until Apply.
INV-7  Apply once mutates session state only.
INV-8  Apply + lock promotes exactly the selected tunables to UserLocked.
INV-9  Replan may never violate hard VRAM/RAM/context/pin constraints.
INV-10 Better measured performance must not silently trade correctness /
       fidelity / context / requested residency.
*/

} // namespace Exec
} // namespace Deep2
