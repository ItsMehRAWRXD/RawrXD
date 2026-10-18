// ============================================================================
// hexmag_finalize_policy.hpp — FINAL authority surface (truth), not sequencing
// ============================================================================
// Architectural freeze (P0C/P0D):
//   controller owns sequencing
//   controller does not own truth
//   FINALIZE_POLICY owns final authority
//
// This file MUST NOT invent new truth rules — it only calls existing
// allowFinal + isAllowedFinalClaim (unchanged).
// ============================================================================
#ifndef RAWRXD_HEXMAG_FINALIZE_POLICY_HPP
#define RAWRXD_HEXMAG_FINALIZE_POLICY_HPP

#include "agentic/HexMagAction.hpp"
#include "core/hexmag_authority.hpp"

#include <string>

namespace RawrXD {
namespace HexMag {

struct FinalizeDecision {
    bool allowed = false;
    ClaimFinalizeClass finClass = ClaimFinalizeClass::Unverified;
    bool allowFinalGate = false;
    bool isAllowedFinalClaimGate = false;
    std::string reason;
};

/// Sole FINAL authority adapter. Sequencing code must call this — never invent FINAL.
inline FinalizeDecision evaluateFinalize(const Claim& claim) {
    FinalizeDecision d;
    if (claim.state == ClaimState::Proven) d.finClass = ClaimFinalizeClass::Proven;
    else if (claim.state == ClaimState::Verified || claim.verified())
        d.finClass = ClaimFinalizeClass::Verified;
    else if (claim.state == ClaimState::MissingInput)
        d.finClass = ClaimFinalizeClass::MissingInput;
    else if (claim.state == ClaimState::Contradicted)
        d.finClass = ClaimFinalizeClass::Contradicted;
    else if (claim.state == ClaimState::FinalRejected)
        d.finClass = ClaimFinalizeClass::Unknown;
    else
        d.finClass = ClaimFinalizeClass::Unverified;

    d.allowFinalGate = allowFinal(claim);
    d.isAllowedFinalClaimGate = isAllowedFinalClaim(d.finClass);
    d.allowed = d.allowFinalGate && d.isAllowedFinalClaimGate;
    if (!d.allowed) {
        if (d.finClass == ClaimFinalizeClass::MissingInput)
            d.reason = "MISSING_INPUT";
        else
            d.reason = "FINAL_DENIED: allowFinal/isAllowedFinalClaim";
    } else {
        d.reason = "FINAL_ALLOWED";
    }
    return d;
}

} // namespace HexMag
} // namespace RawrXD

#endif
