#ifndef D2_DAILY_STREAMER_LIVE_H
#define D2_DAILY_STREAMER_LIVE_H

#include "d2_engine_ssvk_decode_bind.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*D2ModelOpenFn)(void* user, const char* path);
typedef int (*D2ModelCloseFn)(void* user);
typedef int (*D2TokenizePrefillFn)(void* user, const char* prompt, size_t bytes);
typedef int (*D2EmitFn)(void* user, uint32_t token_id, const char* utf8, size_t bytes);

typedef struct D2DailyOps {
    void* user;
    D2ModelOpenFn open_model;
    D2ModelCloseFn close_model;
    D2TokenizePrefillFn tokenize_prefill;
    D2EmitFn emit;
} D2DailyOps;

typedef struct D2DailyStreamer {
    D2DailyOps ops;
    D2DecodeBind* bind;
    uint64_t generations;
    uint64_t generated_tokens;
    uint64_t resets;
    uint64_t opens;
    uint64_t closes;
    uint64_t authority_failures;
    uint32_t model_open;
    uint32_t cancel_requested;
} D2DailyStreamer;

int d2_daily_init(D2DailyStreamer* s, D2DecodeBind* bind, const D2DailyOps* ops);
int d2_daily_open_model(D2DailyStreamer* s, const char* path);
int d2_daily_generate(
    D2DailyStreamer* s,
    const char* prompt, size_t prompt_bytes,
    uint64_t max_new_tokens);
void d2_daily_cancel(D2DailyStreamer* s);
int d2_daily_reset_context(D2DailyStreamer* s);
int d2_daily_close_model(D2DailyStreamer* s);

#ifdef __cplusplus
}
#endif
#endif
