#pragma once
/* C ABI matching KN_O3KKEN.inc */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    KN_OK = 1,
    KN_ERR_NULL = -1,
    KN_ERR_OBJECT = -2,
    KN_ERR_GENERATION = -3,
    KN_ERR_BUSY = -4,
    KN_ERR_OWNER = -5,
    KN_ERR_NOT_READY = -6,
    KN_ERR_PREFETCH = -7,
    KN_ERR_CONSUMER = -8,
    KN_ERR_CLOCK = -9
};

enum { KN_STATE_READY = 1, KN_STATE_HANDED_OFF = 2, KN_STATE_CONSUMED = 4,
       KN_STATE_FAILED = 8 };
enum { KN_FLAG_PREFETCH_HOST = 1 };

#pragma pack(push, 8)
typedef struct KN_CHAIR {
    uint64_t object_id;
    uint64_t generation;
    uint64_t owner;
    uint64_t state;
    void* payload_ptr;
    uint64_t payload_bytes;
    uint64_t ready_qpc;
} KN_CHAIR;

typedef struct KN_VENTI KN_VENTI;
typedef int64_t (*KN_ConsumerFn)(KN_CHAIR* chair, KN_VENTI* venti, uint64_t* result_out);

typedef struct KN_VENTI {
    KN_CHAIR* chair_ptr;
    uint64_t object_id;
    uint64_t generation;
    uint64_t owner_from;
    uint64_t owner_to;
    KN_ConsumerFn consumer_fn;
    void* src_ptr;
    uint64_t copy_bytes;
    uint64_t need_qpc;
    uint64_t flags;
} KN_VENTI;

typedef struct KN_RECEIPT {
    uint64_t status;
    uint64_t result;
    uint64_t start_qpc;
    uint64_t ready_qpc;
    uint64_t handoff_qpc;
    uint64_t consumer_start_qpc;
    uint64_t consumer_end_qpc;
    uint64_t commit_qpc;
    uint64_t qpc_freq;
    uint64_t token_wall_ns;
    uint64_t exposed_wait_ns;
    uint64_t object_id;
    uint64_t generation;
    uint64_t owner_to;
} KN_RECEIPT;
#pragma pack(pop)

/* rcx=venti rdx=receipt; rax=status (KN_OK=1 or KN_ERR_*) */
int64_t KN_O3KKEN(KN_VENTI* venti, KN_RECEIPT* receipt);
int64_t K3C_ConsumeResolved(KN_CHAIR* chair, KN_VENTI* venti, uint64_t* result_out);

#ifdef __cplusplus
}
#endif
