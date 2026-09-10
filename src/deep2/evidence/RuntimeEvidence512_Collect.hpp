/* RuntimeEvidence512_Collect.hpp — harvest COMMITTED records only.
 * Collection side. Never invents claim payloads. Missing claim =
 * NO_CORRESPONDING_RUNTIME_EVIDENCE (report only). */
#pragma once
#include "RuntimeEvidence512.h"
#include <cstdio>
#include <cstring>

namespace Deep2 {
namespace EvCollect {

inline const char* ClaimName(uint32_t id) {
    switch (id) {
    case CLAIM_FIRST_TOKEN_BOUNDARY: return "FIRST_TOKEN_BOUNDARY";
    case CLAIM_HIDDEN_PROBE: return "HIDDEN_PROBE";
    case CLAIM_HIDDEN_LAST: return "HIDDEN_LAST";
    case CLAIM_BOUNDED: return "BOUNDED";
    case CLAIM_VALID: return "VALID";
    case CLAIM_LOGITS_ENTRY: return "LOGITS_ENTRY";
    case CLAIM_LOGITS_COMPLETE: return "LOGITS_COMPLETE";
    case CLAIM_ATTN_COMPLETE: return "ATTN_COMPLETE";
    case CLAIM_PATHB_COMPLETE: return "PATHB_COMPLETE";
    case CLAIM_STREAM_COMPLETE: return "STREAM_COMPLETE";
    case CLAIM_STREAM_ABORT: return "STREAM_ABORT";
    case CLAIM_TEARDOWN_ENTRY: return "TEARDOWN_ENTRY";
    case CLAIM_TEARDOWN_COMPLETE: return "TEARDOWN_COMPLETE";
    case CLAIM_TEARDOWN_FAULT: return "TEARDOWN_FAULT";
    case CLAIM_WALL_NS: return "WALL_NS";
    case CLAIM_DECODE_TPS_Q32_32: return "DECODE_TPS_Q32_32";
    case CLAIM_PARITY: return "PARITY";
    default: return "UNKNOWN_CLAIM";
    }
}

inline bool RecordCommitted(const EvidenceRecord& r) {
    return r.magic == EVREC_MAGIC_U32 && r.version == EVREC_VERSION_U16 &&
           r.recordBytes == EVREC_BYTES_U16 &&
           r.commit == EVREC_COMMIT_U64 && r.seqCap == SEQ_CAP_REQUIRED_U32;
}

/* Walk slots [0, min(writeIndex,capacity)). Skip incomplete. */
inline uint64_t CollectCommitted(const EvidenceState* st, FILE* out) {
    if (!st || !st->buffer || !out) return 0;
    uint64_t n = st->writeIndex;
    if (n > st->capacity) n = st->capacity;
    uint64_t emitted = 0;
    for (uint64_t i = 0; i < n; ++i) {
        const EvidenceRecord& r = st->buffer[i];
        if (!RecordCommitted(r)) continue;
        std::fprintf(out,
                     "RXEV_COLLECT CLAIM=%s ID=%u STATUS=%u RUN=%llu "
                     "ORD=%llu SEQ=%u ARG0=%llu ARG1=%llu\n",
                     ClaimName(r.claimId), r.claimId, r.status,
                     (unsigned long long)r.runId,
                     (unsigned long long)r.ordinal, r.seqCap,
                     (unsigned long long)r.arg0,
                     (unsigned long long)r.arg1);
        ++emitted;
    }
    std::fprintf(out,
                 "RXEV_COLLECT_SUMMARY COMMITTED_LINES=%llu "
                 "WRITE_INDEX=%llu CAP=%llu DROPPED=%llu\n",
                 (unsigned long long)emitted,
                 (unsigned long long)st->writeIndex,
                 (unsigned long long)st->capacity,
                 (unsigned long long)st->dropped);
    std::fflush(out);
    return emitted;
}

/* Report claims with zero committed records — not fabricated observations. */
inline void ReportUncollected(const EvidenceState* st, FILE* out) {
    if (!st || !out) return;
    uint8_t seen[CLAIM_ID_MAX + 1];
    std::memset(seen, 0, sizeof(seen));
    uint64_t n = st->buffer ? st->writeIndex : 0;
    if (n > st->capacity) n = st->capacity;
    for (uint64_t i = 0; i < n; ++i) {
        const EvidenceRecord& r = st->buffer[i];
        if (!RecordCommitted(r)) continue;
        if (r.claimId >= 1 && r.claimId <= CLAIM_ID_MAX)
            seen[r.claimId] = 1;
    }
    for (uint32_t id = 1; id <= CLAIM_ID_MAX; ++id) {
        if (seen[id]) continue;
        std::fprintf(out,
                     "RXEV_UNCOLLECTED CLAIM=%s ID=%u "
                     "DISPOSITION=NO_CORRESPONDING_RUNTIME_EVIDENCE\n",
                     ClaimName(id), id);
    }
    std::fflush(out);
}

} // namespace EvCollect
} // namespace Deep2
