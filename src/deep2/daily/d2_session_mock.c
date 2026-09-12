/* d2_session_mock.c — lifecycle smoke only; NOT live model authority */
#include "d2_stream_session.h"
#include "d2_cancel.h"
#include "d2_stream_metrics.h"
#include <string.h>
#include <stdio.h>
int d2_mock_open(void *e, const char *path)
{
    (void)e;
    return path && path[0] ? 1 : 0;
}
int d2_mock_gen(void *e, const D2GenerateRequest *r, D2TokenCallback cb,
                void *user, D2Cancel *c, D2StreamMetrics *m)
{
    static const char *toks[] = { "Hello", " ", "from", " ", "Deep2", "." };
    uint32_t i, n = 6, maxn;
    (void)e; (void)r;
    if (!cb || !m) return 0;
    maxn = r->max_tokens ? r->max_tokens : n;
    if (maxn > n) maxn = n;
    for (i = 0; i < maxn; ++i) {
        if (d2_cancel_requested(c)) { m->cancelled = 1; break; }
        if (!cb(user, 1000u + i, toks[i], strlen(toks[i]))) break;
        m->generated_tokens++;
        if (i == 0) m->ttft_ns = 1000000ull;
    }
    m->wall_ns = 1000000ull * (m->generated_tokens ? m->generated_tokens : 1);
    m->prompt_tokens = r->prompt ? (uint64_t)strlen(r->prompt) / 4ull + 1ull : 0;
    m->sealed_logits_reuse = 0; m->device_lost = 0;
    return m->generated_tokens > 0 ? 1 : 0;
}
void d2_mock_cancel(void *e) { (void)e; }
void d2_mock_reset(void *e) { (void)e; }
void d2_mock_close(void *e) { (void)e; }
