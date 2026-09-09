// RuntimeEvidence512.hpp — collection state/record layout (seqCap=512).
#pragma once
#include <cstdint>

namespace Deep2 {
namespace Ev512 {

constexpr uint32_t kSeqCap = 512;
constexpr uint32_t kRecMagic = 0x56455852u;
constexpr uint16_t kRecVersion = 1;
constexpr uint16_t kRecBytes = 64;
constexpr uint64_t kRecCommit = 0x0A11CE55A11CE55ull;

enum ClaimId : uint32_t {
    CLAIM_FIRST_TOKEN_BOUNDARY = 1,
    CLAIM_HIDDEN_PROBE = 2,
    CLAIM_HIDDEN_LAST = 3,
    CLAIM_BOUNDED = 4,
    CLAIM_VALID = 5,
    CLAIM_LOGITS_ENTRY = 6,
    CLAIM_LOGITS_COMPLETE = 7,
    CLAIM_ATTN_COMPLETE = 8,
    CLAIM_PATHB_COMPLETE = 9,
    CLAIM_STREAM_COMPLETE = 10,
    CLAIM_STREAM_ABORT = 11,
    CLAIM_TEARDOWN_ENTRY = 12,
    CLAIM_TEARDOWN_COMPLETE = 13,
    CLAIM_TEARDOWN_FAULT = 14,
    CLAIM_WALL_NS = 15,
    CLAIM_DECODE_TPS_Q32_32 = 16,
    CLAIM_PARITY = 17,
    CLAIM_ID_MAX = 17
};

enum Status : uint32_t {
    ST_FALSE = 0, ST_TRUE = 1, ST_ENTER = 2, ST_COMPLETE = 3,
    ST_ABORT = 4, ST_FAULT = 5, ST_OBSERVED = 6
};

#pragma pack(push, 1)
struct EvidenceRecord {
    uint32_t magic;
    uint16_t version;
    uint16_t recordBytes;
    uint32_t claimId;
    uint32_t status;
    uint64_t runId;
    uint64_t ordinal;
    uint32_t seqCap;
    uint32_t reserved;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t commit;
};
struct EvidenceState {
    EvidenceRecord* buffer;
    uint64_t capacity;
    uint64_t writeIndex;
    uint64_t dropped;
    uint64_t runId;
    uint32_t seqCap;
    uint32_t flags;
};
#pragma pack(pop)

static_assert(sizeof(EvidenceRecord) == 64, "EVREC");
static_assert(sizeof(EvidenceState) == 48, "EVS");

inline bool RecordCommitted(const EvidenceRecord& r) noexcept {
    return r.commit == kRecCommit && r.magic == kRecMagic &&
           r.recordBytes == kRecBytes && r.seqCap == kSeqCap;
}

} // namespace Ev512
} // namespace Deep2
