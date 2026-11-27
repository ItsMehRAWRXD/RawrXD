// ReapTransformContext.hpp — RAWRXD P01-P05 request-scoped integration context.
// Composes the verified primitives (placement identity, admission, retirement,
// acquire) into one request-scoped unit the engine consumes. No RNG; no global
// mutable selection state; storage-independent.
#pragma once
#include "reap/ReapPlacementRequest.hpp"
#include "reap/ReapAdmission.hpp"
#include "reap/ReapRetirement.hpp"
#include "reap/ReapTransformAcquire.hpp"
#include <cstdint>

namespace RawrXD::Reap {

class TransformContext {
public:
    TransformContext(PlacementRequest req, uint64_t targetBytes, uint32_t mode)
        : req_(req), target_(targetBytes), mode_(mode) {}

    // P05: admission BEFORE allocation (retirement pressure included).
    bool PlanAdmission(const Capacity& cap, const ModelGeom& g) {
        admission_ = ::RawrXD::Reap::Admit(cap, g, target_, mode_, retire_.Pending());
        return admission_.admit;
    }
    // P02/P03: acquire a transformed expert bound to the identity (post-admission).
    bool Acquire(ExpertProvider& prov, uint32_t layer, uint32_t expert, uint8_t* dst, size_t n) {
        if (!admission_.admit || retire_.Cancelled()) return false;
        auto r = AcquireTransformed(prov, layer, expert, dst, n,
                                    req_.checkpointId, req_.selectionFingerprint,
                                    req_.selectionValid, req_.mode);
        return r.ok;
    }
    uint64_t Identity() const noexcept { return req_.Identity(); }
    RetirementLedger& Retirement() noexcept { return retire_; }
    const Admission& admission() const noexcept { return admission_; }
private:
    PlacementRequest req_;
    uint64_t target_;
    uint32_t mode_;
    Admission admission_;
    RetirementLedger retire_;
};

} // namespace RawrXD::Reap