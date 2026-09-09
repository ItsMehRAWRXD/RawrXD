// RuntimeEvidence512Host.hpp — soft-arm + claim emit wrappers (DEEP2_EV512=1).
#pragma once
#include "RuntimeEvidence512.hpp"
#include "RuntimeEvidence512_EmitDecl.hpp"
#include <cstdlib>

namespace Deep2 {
namespace Ev512 {

inline EvidenceState& HostState() noexcept {
    static EvidenceState s{};
    return s;
}
inline EvidenceRecord* HostBuf() noexcept {
    static EvidenceRecord b[kSeqCap]{};
    return b;
}
inline bool& HostArmed() noexcept {
    static bool a = false;
    return a;
}

inline bool HostTryArm(uint64_t runId) noexcept {
    const char* e = std::getenv("DEEP2_EV512");
    if (!e || e[0] != '1') {
        HostArmed() = false;
        return false;
    }
    /* Idempotent: parent generateStream + K2 must not wipe live buffer. */
    if (HostArmed()) return true;
    if (!EvidenceInit512(&HostState(), HostBuf(), kSeqCap, runId, kSeqCap)) {
        HostArmed() = false;
        return false;
    }
    HostArmed() = true;
    return true;
}

inline void HostEmitFirstTokenBoundary(uint64_t a0, uint64_t a1) noexcept {
    if (HostArmed()) EvidenceEmitFirstTokenBoundary(&HostState(), a0, a1);
}
inline void HostEmitHiddenProbe(uint64_t a0, uint64_t a1) noexcept {
    if (HostArmed()) EvidenceEmitHiddenProbe(&HostState(), a0, a1);
}
inline void HostEmitHiddenLast(uint64_t a0, uint64_t a1) noexcept {
    if (HostArmed()) EvidenceEmitHiddenLast(&HostState(), a0, a1);
}
inline void HostEmitBounds(uint64_t a0, uint64_t a1, uint32_t ok) noexcept {
    if (HostArmed()) EvidenceEmitBounds(&HostState(), a0, a1, ok);
}
inline void HostEmitValid(uint64_t a0, uint64_t a1, uint32_t ok) noexcept {
    if (HostArmed()) EvidenceEmitValid(&HostState(), a0, a1, ok);
}
inline void HostEmitLogitsEntry(uint64_t a0, uint64_t a1) noexcept {
    if (HostArmed()) EvidenceEmitLogitsEntry(&HostState(), a0, a1);
}
inline void HostEmitLogitsComplete(uint64_t a0, uint64_t a1) noexcept {
    if (HostArmed()) EvidenceEmitLogitsComplete(&HostState(), a0, a1);
}
inline void HostEmitAttnComplete(uint64_t a0, uint64_t a1) noexcept {
    if (HostArmed()) EvidenceEmitAttnComplete(&HostState(), a0, a1);
}
inline void HostEmitPathBComplete(uint64_t a0, uint64_t a1) noexcept {
    if (HostArmed()) EvidenceEmitPathBComplete(&HostState(), a0, a1);
}
inline void HostEmitStreamComplete(uint64_t a0, uint64_t a1 = 0) noexcept {
    if (HostArmed()) EvidenceEmitStreamComplete(&HostState(), a0, a1);
}
inline void HostEmitStreamAbort(uint64_t a0, uint64_t a1) noexcept {
    if (HostArmed()) EvidenceEmitStreamAbort(&HostState(), a0, a1);
}
inline void HostEmitTeardownEntry(uint64_t a0 = 0, uint64_t a1 = 0) noexcept {
    if (HostArmed()) EvidenceEmitTeardownEntry(&HostState(), a0, a1);
}
inline void HostEmitTeardownComplete(uint64_t a0 = 0,
                                     uint64_t a1 = 0) noexcept {
    if (HostArmed()) EvidenceEmitTeardownComplete(&HostState(), a0, a1);
}
inline void HostEmitTeardownFault(uint64_t a0, uint64_t a1 = 0) noexcept {
    if (HostArmed()) EvidenceEmitTeardownFault(&HostState(), a0, a1);
}
inline void HostEmitWallNs(uint64_t a0, uint64_t a1 = 0) noexcept {
    if (HostArmed()) EvidenceEmitWallNs(&HostState(), a0, a1);
}
inline void HostEmitDecodeTpsQ32_32(uint64_t a0, uint64_t a1 = 0) noexcept {
    if (HostArmed()) EvidenceEmitDecodeTpsQ32_32(&HostState(), a0, a1);
}
inline void HostEmitParity(uint64_t a0, uint64_t a1, uint32_t ok) noexcept {
    if (HostArmed()) EvidenceEmitParity(&HostState(), a0, a1, ok);
}

} // namespace Ev512
} // namespace Deep2
