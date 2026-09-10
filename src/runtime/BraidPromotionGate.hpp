#pragma once
// BraidPromotionGate — endurance + invariant before baseline install.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "CandidateBindingPolicy.hpp"
#include "ReadbackBoundaryPolicy.hpp"
#include <cstdint>

namespace rawrxd::runtime {

struct PromotionWitness {
    SurvivalInvariant invariant;
    uint8_t parity_all;
    uint8_t purity_all;
    uint8_t product_path_all;
    uint8_t endurance_complete;
    uint64_t median_wall_ns;
    uint64_t baseline_wall_ns;
    uint8_t readback_poison; // 1 if any illegal GPU→host→GPU observed
};

enum class PromoteVerdict : uint8_t {
    Promote = 1,
    RetainAsCandidate = 2,
    Reject = 3
};

inline PromoteVerdict DecidePromotion(const PromotionWitness& w,
                                      CandidateClass klass) {
    if (w.readback_poison) return PromoteVerdict::Reject;
    if (!InvariantHolds(w.invariant)) return PromoteVerdict::Reject;
    if (!w.parity_all || !w.purity_all || !w.product_path_all)
        return PromoteVerdict::Reject;
    if (ClassMayPromoteAlone(klass)) return PromoteVerdict::Reject;
    if (!w.endurance_complete) return PromoteVerdict::RetainAsCandidate;
    if (w.median_wall_ns == 0 || w.baseline_wall_ns == 0)
        return PromoteVerdict::RetainAsCandidate;
    if (w.median_wall_ns < w.baseline_wall_ns) return PromoteVerdict::Promote;
    return PromoteVerdict::RetainAsCandidate;
}

} // namespace rawrxd::runtime
