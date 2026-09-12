/* d2_token_sink.c */
#include "d2_token_sink.h"
void d2_sink_reset(D2TokenSink *s)
{
    if (!s) return;
    s->n = 0; s->drop = 0;
}
int d2_sink_push(D2TokenSink *s, uint32_t token_id)
{
    if (!s) return 0;
    if (s->n >= D2_SINK_CAP) { s->drop++; return 0; }
    s->ids[s->n++] = token_id;
    return 1;
}
