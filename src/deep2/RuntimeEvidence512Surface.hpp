// RuntimeEvidence512Surface.hpp — surface claims 1..96 at every exit.
// OBSERVED only if FindClaim returns a committed record; else NO_CORRESPONDING.
#pragma once
#include "RuntimeEvidence512Host.hpp"
#include "RuntimeEvidence512HostIDE.hpp"
#include "RuntimeEvidence512_CollectDecl.hpp"
#include "RuntimeEvidence512Collect.hpp"
#include "lavapath/RxRunStateHooks.hpp"
#include <cstdio>

namespace Deep2 {
namespace Ev512 {

inline const char* ClaimName96(uint32_t id) noexcept {
    if (id >= 1 && id <= CLAIM_ID_MAX) return ClaimName(id);
    static char buf[32];
    std::snprintf(buf, sizeof(buf), "CLAIM_%u", id);
    return buf;
}

inline void HostSurfaceAllClaims(FILE* out) noexcept {
    if (!out) return;
    if (!HostArmed()) {
        std::fprintf(out, "RXEV_SURFACE ARMED=0 DISPOSITION=NO_RUN_STATE\n");
        std::fflush(out);
        rxow::OnTeardownNoRunState();
        return;
    }
    EvidenceState512* st = HostState512();
    EvidenceIDESummary512 sum{};
    const int sumOk = EvidenceSummarizeIDE512(st, &sum);
    std::fprintf(out,
                 "RXEV_SUMMARY OK=%d RUN=%llu RES=%llu CAP=%llu COM=%llu "
                 "DROP=%llu MASKLO=0x%llx MASKHI=0x%llx INV=%llu INC=%llu "
                 "SEQ=%u FLAGS=0x%x MAX=%u\n",
                 sumOk, (unsigned long long)sum.RunId,
                 (unsigned long long)sum.ReservedRaw,
                 (unsigned long long)sum.Capacity,
                 (unsigned long long)sum.CommittedValid,
                 (unsigned long long)sum.Dropped,
                 (unsigned long long)sum.ClaimMaskLo,
                 (unsigned long long)sum.ClaimMaskHi,
                 (unsigned long long)sum.Invalid,
                 (unsigned long long)sum.Incomplete, sum.SeqCap, sum.Flags,
                 sum.MaxClaimId);
    const uint32_t maxId = sum.MaxClaimId ? sum.MaxClaimId
                                          : (uint32_t)RAWRXD_EVIDENCE_IDE_CLAIM_MAX;
    for (uint32_t id = 1; id <= maxId; ++id) {
        const EvidenceRecord512* r = EvidenceFindIDEClaim512(st, id);
        if (r && r->Commit == kRecCommit) {
            std::fprintf(out,
                         "RXEV_SURFACE CLAIM=%s ID=%u DISPOSITION=OBSERVED "
                         "STATUS=%u ORD=%llu ARG0=%llu ARG1=%llu\n",
                         ClaimName96(id), id, r->Status,
                         (unsigned long long)r->Ordinal,
                         (unsigned long long)r->Arg0,
                         (unsigned long long)r->Arg1);
        } else {
            std::fprintf(out,
                         "RXEV_SURFACE CLAIM=%s ID=%u "
                         "DISPOSITION=NO_CORRESPONDING_RUNTIME_EVIDENCE\n",
                         ClaimName96(id), id);
        }
    }
    std::fflush(out);
}

/* Surfaces on every return/abort once armed — fixes join-only miss. */
struct HostSurfaceGuard {
    FILE* out;
    explicit HostSurfaceGuard(FILE* f) noexcept : out(f ? f : stderr) {}
    ~HostSurfaceGuard() { HostSurfaceAllClaims(out); }
};

} // namespace Ev512
} // namespace Deep2
