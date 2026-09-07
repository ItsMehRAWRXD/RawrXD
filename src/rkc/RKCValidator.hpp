// RKCValidator.hpp — strict epistemic promotions (never SYNTHETIC→REAL)
#pragma once
#include "RKCTypes.hpp"

namespace RawrXD {
namespace RKC {

struct PromoteResult {
    bool ok = false;
    EpistemicState next = EpistemicState::Invalid;
    const char* reason = "";
};

// Allowed transitions only. SYNTHETIC→REAL is always rejected.
PromoteResult TryPromote(EpistemicState from, EpistemicState to, bool fromObservation);

// Observation creates REAL (from Unknown / Inferred / NotObserved).
PromoteResult ObserveToReal(EpistemicState from);

// Validated synthetic becomes DERIVED only.
PromoteResult ValidateSynthetic(bool verifiedFromRealParents);

} // namespace RKC
} // namespace RawrXD
