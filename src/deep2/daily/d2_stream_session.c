/* d2_stream_session.c — create/destroy/bind/mock query */
#include "d2_session_internal.h"
#include "d2_deep2_binding.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
int d2_mock_open(void *e, const char *path);
int d2_mock_gen(void *e, const D2GenerateRequest *r, D2TokenCallback cb,
                void *user, D2Cancel *c, D2StreamMetrics *m);
void d2_mock_cancel(void *e);
void d2_mock_reset(void *e);
void d2_mock_close(void *e);
void d2_session_tracef(const Deep2StreamSession *s, const char *fmt, ...)
{
    va_list ap;
    if (!s || !s->trace) return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}
static int env_trace(void)
{
    const char *e = getenv("RAWRXD_D2_SESSION_TRACE");
    return e && e[0] == '1';
}
Deep2StreamSession *d2_session_create(void)
{
    Deep2StreamSession *s = (Deep2StreamSession *)calloc(1, sizeof *s);
    if (!s) return 0;
    d2_cancel_clear(&s->cancel);
    d2_metrics_reset(&s->metrics);
    d2_sink_reset(&s->sink);
    s->mock_backend = 1;
    s->trace = env_trace();
    s->fn_open = d2_mock_open; s->fn_gen = d2_mock_gen;
    s->fn_cancel = d2_mock_cancel; s->fn_reset = d2_mock_reset;
    s->fn_close = d2_mock_close;
    return s;
}
void d2_session_set_trace(Deep2StreamSession *s, int on)
{
    if (s) s->trace = on ? 1 : 0;
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
    d2_session_tracef(s, "BACKEND=DEEP2_ENGINE MOCK_BACKEND=0\n");
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
