/* RuntimeEvidence512.h — ABI for claim-isolated seqCap=512 evidence.
 * Collection/reader side. No CRT required in MASM producers.
 * Callers own EvidenceState + EvidenceRecord[]. */
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EVREC_MAGIC_U32     0x56455852u /* "RXEV" LE */
#define EVREC_VERSION_U16   1u
#define EVREC_BYTES_U16     64u
#define EVREC_COMMIT_U64    0x0A11CE55A11CE55ull
#define SEQ_CAP_REQUIRED_U32 512u

typedef enum EvStatus {
    EV_STATUS_FALSE = 0,
    EV_STATUS_TRUE = 1,
    EV_STATUS_ENTER = 2,
    EV_STATUS_COMPLETE = 3,
    EV_STATUS_ABORT = 4,
    EV_STATUS_FAULT = 5,
    EV_STATUS_OBSERVED = 6
} EvStatus;

typedef enum EvClaimId {
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
} EvClaimId;

#pragma pack(push, 1)
typedef struct EvidenceRecord {
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
    uint64_t commit; /* EVREC_COMMIT_U64 when complete; else ignore */
} EvidenceRecord;
#pragma pack(pop)

typedef struct EvidenceState {
    EvidenceRecord* buffer;
    uint64_t capacity;
    uint64_t writeIndex;
    uint64_t dropped;
    uint64_t runId;
    uint32_t seqCap;
    uint32_t flags;
} EvidenceState;

/* EvidenceSummary512 — read-only collector output (72 bytes). */
#define EVSUMF_SEQCAP_OK         0x00000001u
#define EVSUMF_RESERVED_COMPLETE 0x00000002u
#define EVSUMF_RECORDS_VALID     0x00000004u
#define EVSUMF_NO_DROPS          0x00000008u
#define EVSUMF_CLOSED_SNAPSHOT   0x00000010u

typedef struct EvidenceSummary512 {
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
} EvidenceSummary512;

/* Producers (MASM). Collection does not call emitters. */
int EvidenceInit512(EvidenceState* st, EvidenceRecord* buf, uint64_t cap,
                    uint64_t runId, uint32_t seqCap /* fifth via stack */);
/* Note: EvidenceInit512 5th arg is Win64 stack [rsp+28h] after home —
 * prefer calling from MASM or a thin asm trampoline. Reset is C-callable: */
int EvidenceResetRun512(EvidenceState* st, uint64_t runId, uint32_t seqCap);
uint64_t EvidenceGetCommittedCount(const EvidenceState* st);
uint64_t EvidenceGetDroppedCount(const EvidenceState* st);

/* Read-only collectors (MASM Collect.obj). Never fabricate missing claims. */
int EvidenceSummarize512(const EvidenceState* st, EvidenceSummary512* out);
const EvidenceRecord* EvidenceFindClaim512(const EvidenceState* st,
                                           uint32_t claimId);
uint64_t EvidenceCopyCommitted512(const EvidenceState* st,
                                  EvidenceRecord* dst, uint64_t dstCap);

#ifdef __cplusplus
}
#endif
