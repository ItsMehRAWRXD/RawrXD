// ============================================================================
// EvidenceStatusEvent.cpp — RAWRXD_EVIDENCE_STATUS_EVENT_001
//
// PublishEvidenceStatus emits evidence status into the runtime telemetry
// stream.  In a full Win32IDE build the panel consumer subscribes to the
// event bus; in standalone builds stderr carries the signal.
// ============================================================================

#include "rawrxd/closure/EvidenceStatusEvent.hpp"
#include <cstdio>

namespace rawrxd {
namespace closure {

void PublishEvidenceStatus(const EvidenceStatusEvent& event) {
    const char* stateStr = to_string(event.status.state);
    const char* capExtra = event.status.capabilityAbsent ? " | CAPABILITY_ABSENT" : "";

    std::fprintf(stderr,
        "[EvidenceStatusEvent] seq=%llu state=%s%s promote=%d taskComplete=%d reason=\"%s\" observations=%zu\n",
        static_cast<unsigned long long>(event.sequenceId),
        stateStr,
        capExtra,
        event.status.promoteAllowed ? 1 : 0,
        event.status.taskCompleteAllowed ? 1 : 0,
        event.status.reason.c_str(),
        event.observations.size());

    // CapabilityAbsent explicit rendering
    if (event.status.capabilityAbsent) {
        std::fprintf(stderr,
            "[EvidenceStatusEvent] capabilityAbsent=1 capabilityReason=\"%s\"\n",
            event.status.capabilityReason.c_str());
    }
}

} // namespace closure
} // namespace rawrxd
