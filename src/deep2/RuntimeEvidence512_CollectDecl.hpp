// RuntimeEvidence512_CollectDecl.hpp — read-only collector (matches Collect.asm).
#pragma once
#include "RuntimeEvidence512.hpp"
#include <cstdint>

namespace Deep2 {
namespace Ev512 {

#pragma pack(push, 1)
struct EvidenceSummary {
    uint64_t runId;
    uint64_t reserved;
    uint64_t capacity;
    uint64_t committed;
    uint64_t dropped;
    uint64_t claimMask;
    uint64_t invalid;
    uint64_t incomplete;
    uint32_t seqCap;
    uint32_t flags;
};
#pragma pack(pop)

static_assert(sizeof(EvidenceSummary) == 72, "EVSUM");

constexpr uint32_t SUM_SEQCAP_OK = 0x01;
constexpr uint32_t SUM_RESERVED_COMPLETE = 0x02;
constexpr uint32_t SUM_RECORDS_VALID = 0x04;
constexpr uint32_t SUM_NO_DROPS = 0x08;
constexpr uint32_t SUM_CLOSED_SNAPSHOT = 0x10;

} // namespace Ev512
} // namespace Deep2

extern "C" {
int EvidenceSummarize512(const Deep2::Ev512::EvidenceState* st,
                         Deep2::Ev512::EvidenceSummary* out);
/* Exact ClaimId 1..17; rax = latest valid record* or nullptr. No cross-claim. */
const Deep2::Ev512::EvidenceRecord*
EvidenceFindClaim512(const Deep2::Ev512::EvidenceState* st, uint32_t claimId);
uint64_t EvidenceCopyCommitted512(const Deep2::Ev512::EvidenceState* st,
                                  Deep2::Ev512::EvidenceRecord* out,
                                  uint64_t outCap);
}
