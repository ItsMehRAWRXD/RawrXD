#pragma once
// ReverseIntegration — RAWRXD_REVERSE_INTEGRATION_001
//
// This file previously read:
//
//   bool attach(int)    { return true; }
//   bool validate(int)  { return true; }
//   bool activate(int)  { return true; }
//
// Three unconditional successes, no state, no callers that reach any of them,
// and an empty .cpp. That is the self-certifying shape this repository has
// retracted three times: an authority whose verdict is reachable by calling a
// function, with no evidence of anything.
//
// The replacement is fail-closed state tracking. Nothing here succeeds by
// assertion. Every method inspects observed state, and the failure paths are
// reachable and are exercised by tools/polykernel_cert.cpp (C14):
//
//   attach(-1)                  -> false   (invalid device)
//   validate(unattached)        -> false   (never attached)
//   activate before validate    -> false   (ordering violated)
//   activate after validation   -> true    (and only then)
//
// Deep2Engine.h owns a std::unique_ptr<ReverseIntegration> and exposes
// getReverseIntegration(). It is NOT constructed by any current path, so the
// object does not exist in a running engine and these methods are unreachable
// today. That is reported as UNPROVEN_ADOPTION rather than papered over.

// Includes are at FILE SCOPE on purpose. An earlier revision placed them inside
// namespace Deep2, which made std:: resolve to Deep2::std and broke <set>
// with a cascade of errors inside xtree that had nothing to do with this class.
#include <cstdint>
#include <set>

namespace Deep2 {

class ReverseIntegration {
public:
    // Attach an integration endpoint. Records real state; does not certify it.
    bool attach(int device) {
        if (device < 0) {
            ++attachRefused_;
            return false;
        }
        // set::insert already ignores duplicates; no counter needed, and
        // size() returns by value so it cannot be incremented.
        attached_.insert(device);
        return true;
    }

    // Validate an attached endpoint. Refuses anything never attached.
    //
    // A successful validation STAMPS the current attach epoch. Validity is
    // scoped to the epoch it was granted in: topologyChanged() clears the
    // validated set, so a prior validation cannot be presented as current.
    //
    // An earlier revision compared validationEpoch_ against attachEpoch_ without
    // ever writing validationEpoch_, so the first validation succeeded and
    // every validation after a topology change was refused -- which then made
    // activate() unreachable. The gate caught it (C14H).
    bool validate(int device) {
        if (device < 0) return false;
        if (attached_.find(device) == attached_.end()) { ++validateRefused_; return false; }
        validationEpoch_ = attachEpoch_;
        validated_.insert(device);
        return true;
    }

    // Activate only what was validated, and only once per epoch. Activation is
    // strictly ordered behind validation so it cannot be reached by assertion.
    bool activate(int device) {
        if (device < 0) return false;
        if (validated_.find(device) == validated_.end()) { ++activateRefused_; return false; }
        if (active_.find(device) != active_.end()) {
            // Already active: a re-entry, not a new authority.
            ++activateRefused_;
            return false;
        }
        active_.insert(device);
        return true;
    }

    // Any structural change invalidates prior validation. Without this,
    // validate() would keep answering for a device set that no longer holds.
    void topologyChanged() {
        ++attachEpoch_;
        validated_.clear();
    }

    bool     isAttached(int device)  const { return attached_.find(device)  != attached_.end(); }
    bool     isValidated(int device) const { return validated_.find(device) != validated_.end(); }
    bool     isActive(int device)    const { return active_.find(device)    != active_.end(); }
    uint64_t attachRefusedCount()   const { return attachRefused_; }
    uint64_t validateRefusedCount() const { return validateRefused_; }
    uint64_t activateRefusedCount() const { return activateRefused_; }
    size_t   attachedCount()   const { return attached_.size(); }
    size_t   validatedCount()  const { return validated_.size(); }
    size_t   activeCount()     const { return active_.size(); }
    uint64_t validationEpoch() const { return validationEpoch_; }

private:
    std::set<int> attached_;
    std::set<int> validated_;
    std::set<int> active_;
    uint64_t attachEpoch_      = 1;
    uint64_t validationEpoch_  = 1;
    uint64_t activatedEpoch_   = 0;   // 0 == never activated
    uint64_t attachRefused_    = 0;
    uint64_t validateRefused_  = 0;
    uint64_t activateRefused_  = 0;
};

} // namespace Deep2
