/* d2_stream_session.c — session state; backend via D2Deep2Binding */
#include "d2_session_internal.h"
#include "d2_deep2_binding.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int d2_mock_open(void *e, const char *path);
int d2_mock_gen(void *e, const D2GenerateRequest *r, D2TokenCallback cb,
                void *user, D2Cancel *c, D2StreamMetrics *m);
void d2_mock_cancel(void *e);
void d2_mock_reset(void *e);
void d2_mock_close(void *e);
Deep2StreamSession *d2_session_create(void)
{
    Deep2StreamSession *s = (Deep2StreamSession *)calloc(1, sizeof *s);
    if (!s) return 0;
    d2_cancel_clear(&s->cancel);
    d2_metrics_reset(&s->metrics);
    d2_sink_reset(&s->sink);
    s->mock_backend = 1;
    s->fn_open = d2_mock_open; s->fn_gen = d2_mock_gen;
    s->fn_cancel = d2_mock_cancel; s->fn_reset = d2_mock_reset;
    s->fn_close = d2_mock_close;
    return s;
}
int d2_session_install_binding(Deep2StreamSession *s, const D2Deep2Binding *b)
{
    if (!s || !b || !b->engine || !b->load_model || !b->generate) return 0;
    if (s->model_loaded) d2_session_close_model(s);
    s->engine = b->engine;
    s->fn_open = b->load_model;
    s->fn_gen = b->generate;
    s->fn_cancel = b->request_cancel;
    s->fn_reset = b->reset_context;
    s->fn_close = b->unload_model;
    s->mock_backend = 0;
    printf("BACKEND=DEEP2_ENGINE MOCK_BACKEND=0\n");
    fflush(stdout);
    return 1;
}
int d2_session_backend_is_mock(const Deep2StreamSession *s)
{
    return !s || s->mock_backend ? 1 : 0;
}
void d2_session_destroy(Deep2StreamSession *s)
{
    if (!s) return;
    d2_session_close_model(s);
    free(s);
}
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
    printf("DAILY_LOAD_MODEL=PASS path=%s\n", s->model_path);
    fflush(stdout);
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
    d2_metrics_print(&s->metrics);
    printf("DAILY_GENERATION=%s SAME_PROCESS=1 MOCK_BACKEND=%d\n",
           ok ? "PASS" : "FAIL", s->mock_backend);
    fflush(stdout);
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
    printf("DAILY_CONTEXT_RESET=1\n"); fflush(stdout);
}
void d2_session_close_model(Deep2StreamSession *s)
{
    if (!s || !s->model_loaded) return;
    if (s->fn_close) s->fn_close(s->engine);
    s->model_loaded = 0; s->model_path[0] = 0;
    printf("DAILY_UNLOAD_MODEL=PASS\n"); fflush(stdout);
}
int d2_session_model_loaded(const Deep2StreamSession *s)
{
    return s && s->model_loaded ? 1 : 0;
}
uint64_t d2_session_last_generated(const Deep2StreamSession *s)
{
    return s ? s->last_generated : 0;
}
