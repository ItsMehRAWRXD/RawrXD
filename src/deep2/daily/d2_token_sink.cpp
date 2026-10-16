// ============================================================================
// d2_token_sink.cpp — ring-buffer / callback bridge for streamed tokens
//
// Real bounded ring sink: pushes accepted tokens, counts drops when full.
// No fabricated data.
// ============================================================================

#include "d2_token_sink.h"

#include <cstring>

void d2_sink_reset(D2TokenSink *s) {
    if (!s) return;
    std::memset(s->ids, 0, sizeof(s->ids));
    s->n = 0;
    s->drop = 0;
}

int d2_sink_push(D2TokenSink *s, uint32_t token_id) {
    if (!s) return 0;
    if (s->n >= D2_SINK_CAP) {
        ++s->drop;
        return 0;
    }
    s->ids[s->n++] = token_id;
    return 1;
}
