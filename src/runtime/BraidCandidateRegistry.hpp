#pragma once
// BraidCandidateRegistry — inventory of prior ideas as addressable candidates.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "CandidateBindingPolicy.hpp"
#include <cstdint>

namespace rawrxd::runtime {

enum class CandidateKind : uint8_t {
    Kernel = 1,
    Quant = 2,
    Residency = 3,
    Prefetch = 4,
    Scheduling = 5,
    Feature = 6,
    Attention = 7,
    Logits = 8,
    Qkv = 9,
    Composite = 10,
    Slingshot = 11,
    Pinball = 12,
    SBraid = 13,
    Beacon = 14
};

struct BraidCandidate {
    uint64_t candidate_id;
    CandidateKind kind;
    CandidateClass klass;
    CandidateStatus status;
    uint64_t model_hash;
    uint64_t graph_hash;
    uint32_t flags; // bit0=no_readback, bit1=fixed_dest, bit2=prefetch_ok
    const char* name; // stable string id; not owned
};

enum CandidateFlags : uint32_t {
    Cand_None = 0,
    Cand_NoReadback = 1u << 0,
    Cand_FixedDestination = 1u << 1,
    Cand_PrefetchOk = 1u << 2,
    Cand_NoNewOwner = 1u << 3,
    Cand_GpuNativeQuant = 1u << 4,
    Cand_EpochHintOnly = 1u << 5
};

inline bool CandidateLegalForProduct(const BraidCandidate& c,
                                     const SurvivalInvariant& inv) {
    if (!InvariantHolds(inv)) return false;
    if (!ClassMayRunProduct(c.klass)) return false;
    if (c.model_hash == 0 || c.graph_hash == 0) return false;
    if ((c.flags & Cand_NoReadback) == 0 &&
        c.klass == CandidateClass::BlockedReadbackDownward)
        return false;
    return true;
}

} // namespace rawrxd::runtime
