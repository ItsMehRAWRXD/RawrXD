/* d2_token_sink.h — ring-buffer / callback bridge for streamed tokens */
#ifndef D2_TOKEN_SINK_H
#define D2_TOKEN_SINK_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
#define D2_SINK_CAP 256
typedef struct D2TokenSink {
    uint32_t ids[D2_SINK_CAP];
    uint32_t n, drop;
} D2TokenSink;
void d2_sink_reset(D2TokenSink *s);
int d2_sink_push(D2TokenSink *s, uint32_t token_id);
#ifdef __cplusplus
}
#endif
#endif
