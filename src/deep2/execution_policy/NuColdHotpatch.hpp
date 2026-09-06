// ============================================================================
// NuColdHotpatch.hpp — unlock controller: hotpatch without cold reload
//
// COLD_RELOAD / MODEL_UNLOAD / PROCESS_RESTART / ACTIVE_GENERATION_MUTATION
//   = FORBIDDEN on the hot path.
// Generation gate stays: token on N finishes on N; post-swap sees N+1.
// ============================================================================
#pragma once

#include "RealtimeKernel.hpp"
#include <cstdint>
#include <string>

namespace Deep2 {
namespace Exec {

enum class HotPatchRoute : uint8_t {
    HotSafe = 0,     // NUCOLD — build N+1 → validate → freeze → hash → swap
    ColdRequired     // explicit cold disposition (not silent reload)
};

enum class HotPatchStatus : uint8_t {
    Applied = 0,
    ColdPathRequired,
    ValidationFailed,
    CommitFailed,
    ForbiddenActiveMutation
};

struct HotPatchFlags {
    bool requiresWeightReparse = false;
    bool requiresTensorShapeChange = false;
    bool requiresBackendRecreation = false;
    bool breaksActiveImageAbi = false;
    bool mutatesInFlightGeneration = false; // never allowed
};

// What may stay hot (policy / residency / routing / work-avoidance / tunables).
struct HotPatchRequest {
    HotPatchFlags flags;
    RealtimeStateSnapshot candidate; // private build of N+1 overlay
    std::string note;
};

struct HotPatchResult {
    HotPatchStatus status = HotPatchStatus::ValidationFailed;
    HotPatchRoute route = HotPatchRoute::HotSafe;
    uint64_t generation = 0;
    Hash256 imageSha = 0;
    std::string detail;
};

inline HotPatchRoute ClassifyHotPatch(const HotPatchFlags& f) {
    if (f.requiresWeightReparse || f.requiresTensorShapeChange ||
        f.requiresBackendRecreation || f.breaksActiveImageAbi)
        return HotPatchRoute::ColdRequired;
    return HotPatchRoute::HotSafe;
}

inline const char* HotPatchStatusName(HotPatchStatus s) {
    switch (s) {
    case HotPatchStatus::Applied: return "HOTPATCH_APPLIED";
    case HotPatchStatus::ColdPathRequired: return "COLD_PATH_REQUIRED";
    case HotPatchStatus::ValidationFailed: return "VALIDATION_FAILED";
    case HotPatchStatus::CommitFailed: return "COMMIT_FAILED";
    case HotPatchStatus::ForbiddenActiveMutation:
        return "ACTIVE_GENERATION_MUTATION_FORBIDDEN";
    }
    return "?";
}

// Controller unlock: do NOT treat policy/config/routing as cold load.
// Does not remove the generation gate — routes eligible patches through RCU.
inline HotPatchResult ControllerHotPatch(RealtimeEngine& engine,
                                         HotPatchRequest req) {
    HotPatchResult out;
    out.route = ClassifyHotPatch(req.flags);

    if (req.flags.mutatesInFlightGeneration) {
        out.status = HotPatchStatus::ForbiddenActiveMutation;
        out.detail = "ACTIVE_GENERATION_MUTATION_FORBIDDEN";
        return out;
    }
    if (out.route == HotPatchRoute::ColdRequired) {
        out.status = HotPatchStatus::ColdPathRequired;
        out.detail = "COLD_PATH_REQUIRED";
        return out;
    }

    // Acquire N (readers pin old image across commit).
    RealtimeReadView active = engine.AcquireState();
    if (!active.valid()) {
        out.status = HotPatchStatus::ValidationFailed;
        out.detail = "NO_ACTIVE_IMAGE";
        return out;
    }
    const uint64_t genN = active.generation();

    // Private candidate inherits sealed schema/authority; never mutates gen N.
    req.candidate.expectedSchemaHash = engine.kernel().schemaHash;
    req.candidate.expectedAuthorityHash = engine.kernel().authorityHash;
    if (req.candidate.source.empty())
        req.candidate.source = "nucold_hotpatch";

    // Build is caller's responsibility (already in req.candidate).
    // Validate + freeze + hash + atomic swap = CommitRealtimeState.
    CommitResult c = engine.CommitRealtimeState(req.candidate);
    if (!c.ok) {
        out.status = HotPatchStatus::CommitFailed;
        out.detail = c.detail;
        out.generation = genN; // unchanged — rollback-by-non-swap
        return out;
    }

    RealtimeReadView next = engine.AcquireState();
    out.status = HotPatchStatus::Applied;
    out.generation = c.newGeneration;
    out.imageSha = next.valid() ? next.stateImageSha() : 0;
    out.detail = "HOTPATCH_APPLIED gen=" + std::to_string(out.generation) +
                 " from=" + std::to_string(genN);
    // Invariant check for caller: active (N) still readable with same gen.
    (void)active;
    return out;
}

} // namespace Exec
} // namespace Deep2
