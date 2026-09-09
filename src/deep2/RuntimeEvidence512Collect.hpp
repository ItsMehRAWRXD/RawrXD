// RuntimeEvidence512Collect.hpp — harvest committed records only (no fabrications).
#pragma once
#include "RuntimeEvidence512.hpp"
#include <cstddef>

namespace Deep2 {
namespace Ev512 {

inline const char* ClaimName(uint32_t id) noexcept {
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

/* Disposition only — never invents a record. */
inline const char* CollectDisposition(const EvidenceState* st,
                                      uint32_t claimId) noexcept {
    if (!st || !st->buffer || st->seqCap != kSeqCap)
        return "NO_CORRESPONDING_RUNTIME_EVIDENCE";
    const uint64_t n = st->writeIndex < st->capacity ? st->writeIndex
                                                     : st->capacity;
    for (uint64_t i = 0; i < n; ++i) {
        const EvidenceRecord& r = st->buffer[i];
        if (RecordCommitted(r) && r.claimId == claimId)
            return "OBSERVED";
    }
    return "NO_CORRESPONDING_RUNTIME_EVIDENCE";
}

inline size_t CollectScan(const EvidenceState* st, EvidenceRecord* out,
                          size_t outCap) noexcept {
    if (!st || !st->buffer || !out || outCap == 0 || st->seqCap != kSeqCap)
        return 0;
    const uint64_t n = st->writeIndex < st->capacity ? st->writeIndex
                                                     : st->capacity;
    size_t w = 0;
    for (uint64_t i = 0; i < n && w < outCap; ++i) {
        if (RecordCommitted(st->buffer[i]))
            out[w++] = st->buffer[i];
    }
    return w;
}

} // namespace Ev512
} // namespace Deep2
