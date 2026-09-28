#pragma once
// ============================================================================
// EvidenceStatusEvent.hpp — RAWRXD_EVIDENCE_STATUS_EVENT_001
//
// First-class evidence stream event, published independently from Thinking.
// Carries a complete EvidenceStatus snapshot plus the raw observations
// that produced it, suitable for UI rendering beside the Thinking panel.
// ============================================================================

#include "rawrxd/closure/EvidenceStatus.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {
namespace closure {

// ---------------------------------------------------------------------------
// EvidenceStatusEvent — a single evidence snapshot for the UI stream
// ---------------------------------------------------------------------------
struct EvidenceStatusEvent {
    EvidenceStatus              status;       // evaluated classification
    std::vector<EvidenceObservation> observations; // raw witnesses
    uint64_t                    sequenceId = 0; // monotonic event counter
    std::string                 timestamp;    // ISO-8601
};

// ---------------------------------------------------------------------------
// PublishEvidenceStatus — UI API hook
//
// Called after EvidenceAuthority.evaluate() produces a status.
// Implementation lives in the Win32IDE / UI layer.
// ---------------------------------------------------------------------------
void PublishEvidenceStatus(const EvidenceStatusEvent& event);

} // namespace closure
} // namespace rawrxd
