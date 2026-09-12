#ifndef DEEP2_PERSISTENT_DECODE_H
#define DEEP2_PERSISTENT_DECODE_H

#include "deep2_e2e_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*D2PreparePersistentFn)(void* user);
typedef int (*D2EnsureKvFn)(void* user, uint64_t max_context_tokens);
typedef int (*D2PrefetchFn)(void* user, uint64_t token_index);
typedef int (*D2ExecuteTokenFn)(void* user, uint64_t token_index, D2TokenTiming* out_timing);
typedef int (*D2AdvanceKvFn)(void* user, uint64_t token_index);
typedef int (*D2ResetPersistentFn)(void* user);

typedef struct D2PersistentDecodeOps {
    void* user;
    D2PreparePersistentFn prepare_persistent_commands;
    D2EnsureKvFn ensure_persistent_kv;
    D2PrefetchFn prefetch_token;
    D2ExecuteTokenFn execute_token;
    D2AdvanceKvFn advance_kv;
    D2ResetPersistentFn reset;
} D2PersistentDecodeOps;

typedef struct D2PersistentDecode {
    D2PersistentDecodeOps ops;

    uint64_t max_context_tokens;
    uint64_t next_token_index;
    uint64_t prefetched_token_index;

    uint64_t tokens_executed;
    uint64_t rejected_tokens;

    uint32_t commands_ready;
    uint32_t kv_ready;
    uint32_t active;
    uint32_t has_prefetch;

    uint64_t command_rebuilds_after_warmup;
    uint64_t kv_host_roundtrips;
    uint64_t critical_path_nvme_reads;
} D2PersistentDecode;

int d2_pd_open(
    D2PersistentDecode* s,
    const D2PersistentDecodeOps* ops,
    uint64_t max_context_tokens);

int d2_pd_step(
    D2PersistentDecode* s,
    D2TokenTiming* out_timing);

int d2_pd_reset(D2PersistentDecode* s);
void d2_pd_close(D2PersistentDecode* s);

int d2_pd_authority_ready(const D2PersistentDecode* s);

#ifdef __cplusplus
}
#endif
#endif
