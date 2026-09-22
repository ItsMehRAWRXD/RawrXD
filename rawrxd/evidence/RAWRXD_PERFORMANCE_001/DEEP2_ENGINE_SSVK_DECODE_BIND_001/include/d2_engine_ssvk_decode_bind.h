#ifndef D2_ENGINE_SSVK_DECODE_BIND_H
#define D2_ENGINE_SSVK_DECODE_BIND_H

#include "d2_decode_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*D2BeginTokenFn)(void* user, uint64_t token_index);
typedef int (*D2RunFullForwardFn)(void* user, uint64_t token_index, D2DecodeReceipt* io);
typedef int (*D2FinalNormLmHeadFn)(void* user, uint64_t token_index, D2DecodeReceipt* io);
typedef int (*D2SampleCommitFn)(
    void* user, uint64_t token_index,
    uint32_t* out_token_id, const char** out_utf8, size_t* out_utf8_bytes,
    D2DecodeReceipt* io);
typedef int (*D2KvAdvanceFn)(void* user, uint64_t token_index, uint32_t token_id, D2DecodeReceipt* io);
typedef int (*D2PrefetchNextFn)(void* user, uint64_t next_token_index);
typedef int (*D2PreparePersistentFn)(void* user);
typedef int (*D2ResetContextFn)(void* user);

typedef struct D2DecodeBindOps {
    void* user;
    D2PreparePersistentFn prepare_persistent;
    D2BeginTokenFn begin_token;
    D2RunFullForwardFn run_full_forward;
    D2FinalNormLmHeadFn final_norm_lm_head;
    D2SampleCommitFn sample_commit;
    D2KvAdvanceFn kv_advance;
    D2PrefetchNextFn prefetch_next;
    D2ResetContextFn reset_context;
} D2DecodeBindOps;

typedef struct D2DecodeBind {
    D2DecodeBindOps ops;
    uint64_t next_token_index;
    uint64_t tokens_committed;
    uint64_t rejected_tokens;
    uint64_t persistent_prepares;
    uint64_t prefetch_enqueues;
    uint32_t prepared;
    uint32_t active;
} D2DecodeBind;

int d2_decode_bind_open(D2DecodeBind* b, const D2DecodeBindOps* ops);
int d2_decode_bind_one(
    D2DecodeBind* b,
    uint32_t* out_token_id,
    const char** out_utf8,
    size_t* out_utf8_bytes,
    D2DecodeReceipt* out_receipt);
int d2_decode_bind_reset(D2DecodeBind* b);
void d2_decode_bind_close(D2DecodeBind* b);

#ifdef __cplusplus
}
#endif
#endif
