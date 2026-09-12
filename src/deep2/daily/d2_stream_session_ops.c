/* d2_stream_session_ops.c — open/generate/close/reset */
#include "d2_session_internal.h"
#include <string.h>
#include <stdio.h>
void d2_session_tracef(const Deep2StreamSession *s, const char *fmt, ...);
int d2_session_open_model(Deep2StreamSession *s, const char *gguf_path)
{
    if (!s || !gguf_path || !gguf_path[0]) return 0;
    if (s->model_loaded) d2_session_close_model(s);
    if (!s->fn_open || !s->fn_open(s->engine, gguf_path)) return 0;
    memset(s->model_path, 0, sizeof s->model_path);
    memcpy(s->model_path, gguf_path,
           strlen(gguf_path) < sizeof s->model_path - 1
               ? strlen(gguf_path) : sizeof s->model_path - 1);
    s->model_loaded = 1;
    d2_session_tracef(s, "DAILY_LOAD_MODEL=PASS path=%s\n", s->model_path);
    return 1;
}
int d2_session_generate(Deep2StreamSession *s, const D2GenerateRequest *req,
                        D2TokenCallback cb, void *user)
{
    int ok;
    if (!s || !req || !req->prompt || !s->model_loaded || !s->fn_gen) return 0;
    d2_cancel_clear(&s->cancel);
    d2_metrics_reset(&s->metrics);
    s->metrics.request_id = ++s->generations;
    if (!req->continue_context && s->fn_reset) s->fn_reset(s->engine);
    ok = s->fn_gen(s->engine, req, cb, user, &s->cancel, &s->metrics);
    s->last_generated = s->metrics.generated_tokens;
    if (s->trace) d2_metrics_print(&s->metrics);
    d2_session_tracef(s, "DAILY_GENERATION=%s SAME_PROCESS=1 MOCK_BACKEND=%d\n",
                      ok ? "PASS" : "FAIL", s->mock_backend);
    return ok;
}
void d2_session_cancel(Deep2StreamSession *s)
{
    if (!s) return;
    d2_cancel_request(&s->cancel);
    if (s->fn_cancel) s->fn_cancel(s->engine);
}
void d2_session_reset_context(Deep2StreamSession *s)
{
    if (!s) return;
    if (s->fn_reset) s->fn_reset(s->engine);
    d2_session_tracef(s, "DAILY_CONTEXT_RESET=1\n");
}
void d2_session_close_model(Deep2StreamSession *s)
{
    if (!s || !s->model_loaded) return;
    if (s->fn_close) s->fn_close(s->engine);
    s->model_loaded = 0; s->model_path[0] = 0;
    d2_session_tracef(s, "DAILY_UNLOAD_MODEL=PASS\n");
}
int d2_session_model_loaded(const Deep2StreamSession *s)
{
    return s && s->model_loaded ? 1 : 0;
}
uint64_t d2_session_last_generated(const Deep2StreamSession *s)
{
    return s ? s->last_generated : 0;
}
