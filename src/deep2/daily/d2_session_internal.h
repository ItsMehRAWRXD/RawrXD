/* d2_session_internal.h — session fields for adapter bind only */
#ifndef D2_SESSION_INTERNAL_H
#define D2_SESSION_INTERNAL_H
#include "d2_stream_session.h"
#include "d2_cancel.h"
#include "d2_stream_metrics.h"
#include "d2_token_sink.h"
struct Deep2StreamSession {
    int model_loaded;
    int mock_backend;
    int trace; /* 1 → cert/diag lines on stderr */
    char model_path[512];
    D2Cancel cancel;
    D2StreamMetrics metrics;
    D2TokenSink sink;
    uint64_t generations;
    uint64_t last_generated;
    void *engine;
    int (*fn_open)(void *e, const char *path);
    int (*fn_gen)(void *e, const D2GenerateRequest *r, D2TokenCallback cb,
                  void *user, D2Cancel *c, D2StreamMetrics *m);
    void (*fn_cancel)(void *e);
    void (*fn_reset)(void *e);
    void (*fn_close)(void *e);
};
#endif
