/* d2_stream_metrics.h — per-request observability (not TPS authority) */
#ifndef D2_STREAM_METRICS_H
#define D2_STREAM_METRICS_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct D2StreamMetrics {
    uint64_t request_id;
    uint64_t prompt_tokens;
    uint64_t generated_tokens;
    uint64_t ttft_ns;
    uint64_t wall_ns;
    uint32_t cancelled;
    uint32_t device_lost;
    uint32_t sealed_logits_reuse;
} D2StreamMetrics;
void d2_metrics_reset(D2StreamMetrics *m);
void d2_metrics_print(const D2StreamMetrics *m);
#ifdef __cplusplus
}
#endif
#endif
