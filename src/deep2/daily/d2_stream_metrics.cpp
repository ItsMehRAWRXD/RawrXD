// ============================================================================
// d2_stream_metrics.cpp — per-request observability for the daily streamer
//
// Real (non-simulated) metric bookkeeping: counters are only updated by the
// session adapter from actual engine output. No fabricated numbers.
// ============================================================================

#include "d2_stream_metrics.h"

#include <cstdio>

void d2_metrics_reset(D2StreamMetrics *m) {
    if (!m) return;
    m->request_id = 0;
    m->prompt_tokens = 0;
    m->generated_tokens = 0;
    m->ttft_ns = 0;
    m->wall_ns = 0;
    m->cancelled = 0;
    m->device_lost = 0;
    m->sealed_logits_reuse = 0;
}

void d2_metrics_print(const D2StreamMetrics *m) {
    if (!m) return;
    std::printf(
        "d2_stream_metrics{request_id=%llu prompt_tokens=%llu "
        "generated_tokens=%llu ttft_ns=%llu wall_ns=%llu cancelled=%u "
        "device_lost=%u sealed_logits_reuse=%u}\n",
        (unsigned long long)m->request_id, (unsigned long long)m->prompt_tokens,
        (unsigned long long)m->generated_tokens, (unsigned long long)m->ttft_ns,
        (unsigned long long)m->wall_ns, m->cancelled, m->device_lost,
        m->sealed_logits_reuse);
}
