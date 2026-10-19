#ifndef DEEP2_STREAMER_LIVE_H
#define DEEP2_STREAMER_LIVE_H

#include <stdint.h>
#include <stddef.h>
#include "deep2_e2e_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*D2OpenModelFn)(void* user, const char* model_path);
typedef int (*D2CloseModelFn)(void* user);
typedef int (*D2ResetContextFn)(void* user);
typedef int (*D2PrefillFn)(void* user, const char* prompt, size_t prompt_bytes);
typedef int (*D2DecodeOneFn)(
    void* user,
    uint64_t token_index,
    uint32_t* out_token_id,
    const char** out_utf8,
    size_t* out_utf8_bytes,
    D2TokenTiming* out_timing);
typedef int (*D2EmitFn)(void* user, const char* utf8, size_t bytes);

typedef struct D2StreamerOps {
    void* user;
    D2OpenModelFn open_model;
    D2CloseModelFn close_model;
    D2ResetContextFn reset_context;
    D2PrefillFn prefill;
    D2DecodeOneFn decode_one;
    D2EmitFn emit;
} D2StreamerOps;

typedef struct D2Streamer {
    D2StreamerOps ops;

    uint64_t generation_id;
    uint64_t generated_tokens;
    uint64_t total_generated_tokens;
    uint64_t rejected_tokens;

    uint32_t model_open;
    uint32_t generating;
    uint32_t cancel_requested;
    uint32_t context_reused;

    uint32_t external_runtime_calls;
    uint32_t device_lost_seen;
    uint32_t reserved0;
    uint32_t reserved1;
} D2Streamer;

int d2_streamer_init(D2Streamer* s, const D2StreamerOps* ops);
int d2_streamer_open(D2Streamer* s, const char* model_path);
int d2_streamer_generate(
    D2Streamer* s,
    const char* prompt,
    size_t prompt_bytes,
    uint64_t max_new_tokens);
void d2_streamer_cancel(D2Streamer* s);
int d2_streamer_reset(D2Streamer* s);
int d2_streamer_close(D2Streamer* s);

int d2_streamer_e2e_ready(const D2Streamer* s);

#ifdef __cplusplus
}
#endif
#endif
