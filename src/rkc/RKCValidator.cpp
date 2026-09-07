// RKCValidator.cpp — epistemic transition table
#include "RKCValidator.hpp"

namespace RawrXD {
namespace RKC {

PromoteResult TryPromote(EpistemicState from, EpistemicState to, bool fromObservation) {
    if (from == EpistemicState::Synthetic && to == EpistemicState::Real)
        return {false, EpistemicState::Invalid, "SYNTHETIC_TO_REAL_FORBIDDEN"};

    // Absence must not become success by inference.
    if (IsNegativeKnowledge(from) && to == EpistemicState::Derived)
        return {false, from, "NEGATIVE_TO_DERIVED_FORBIDDEN"};
    if (IsNegativeKnowledge(from) && to == EpistemicState::Real) {
        // Only NotObserved may be filled by a fresh observation.
        if (!(fromObservation && from == EpistemicState::NotObserved))
            return {false, from, "NEGATIVE_TO_REAL_FORBIDDEN"};
    }

    if (to == EpistemicState::Real) {
        if (!fromObservation)
            return {false, from, "REAL_REQUIRES_OBSERVATION"};
        if (from == EpistemicState::Unknown || from == EpistemicState::Inferred ||
            from == EpistemicState::NotObserved)
            return {true, EpistemicState::Real, "OBSERVED"};
        if (from == EpistemicState::Synthetic)
            return {false, EpistemicState::Invalid, "SYNTHETIC_TO_REAL_FORBIDDEN"};
        if (from == EpistemicState::Real)
            return {true, EpistemicState::Conflict, "REAL_CONFLICT"};
        return {false, from, "INVALID_TO_REAL"};
    }

    if (to == EpistemicState::Derived) {
        if (from == EpistemicState::Synthetic || from == EpistemicState::Inferred ||
            from == EpistemicState::Unknown)
            return {true, EpistemicState::Derived, "VALIDATED"};
        return {false, from, "INVALID_TO_DERIVED"};
    }

    if (to == EpistemicState::Invalid)
        return {true, EpistemicState::Invalid, "CONTRADICTED"};

    if (to == EpistemicState::Synthetic && from == EpistemicState::Unknown)
        return {true, EpistemicState::Synthetic, "SYNTHESIZED"};

    if (to == EpistemicState::Inferred && from == EpistemicState::Unknown)
        return {true, EpistemicState::Inferred, "HYPOTHESIS"};

    return {false, from, "TRANSITION_DENIED"};
}

PromoteResult ObserveToReal(EpistemicState from) {
    return TryPromote(from, EpistemicState::Real, true);
}

PromoteResult ValidateSynthetic(bool verifiedFromRealParents) {
    if (!verifiedFromRealParents)
        return {false, EpistemicState::Invalid, "PARENTS_NOT_REAL_OR_DERIVED"};
    return TryPromote(EpistemicState::Synthetic, EpistemicState::Derived, false);
}

} // namespace RKC
} // namespace RawrXD
