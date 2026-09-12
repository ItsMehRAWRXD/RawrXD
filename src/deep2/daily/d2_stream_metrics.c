/* d2_stream_metrics.c — metrics reset + stderr print (trace path) */
#include "d2_stream_metrics.h"
#include <stdio.h>
#include <string.h>
void d2_metrics_reset(D2StreamMetrics *m)
{
    if (!m) return;
    memset(m, 0, sizeof *m);
}
void d2_metrics_print(const D2StreamMetrics *m)
{
    if (!m) return;
    fprintf(stderr, "D2_REQ_ID=%llu PROMPT_TOK=%llu GEN_TOK=%llu\n",
            (unsigned long long)m->request_id,
            (unsigned long long)m->prompt_tokens,
            (unsigned long long)m->generated_tokens);
    fprintf(stderr, "TTFT_NS=%llu WALL_NS=%llu CANCELLED=%u DEVICE_LOST=%u\n",
            (unsigned long long)m->ttft_ns, (unsigned long long)m->wall_ns,
            m->cancelled, m->device_lost);
    fprintf(stderr,
            "SEALED_LOGITS_REUSE=%u FULL_MODEL_TPS_AUTHORITY=0 PROMOTE=0\n",
            m->sealed_logits_reuse);
    fflush(stderr);
}
