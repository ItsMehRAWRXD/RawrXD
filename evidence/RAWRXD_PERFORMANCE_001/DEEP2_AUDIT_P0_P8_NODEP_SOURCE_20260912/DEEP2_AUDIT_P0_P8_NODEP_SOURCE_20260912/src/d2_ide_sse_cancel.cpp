#include "deep2_audit_nodep.h"
#include <string.h>

static int wr(D2SseSink* s, const void* p, uint32_t n) { return s->write_bytes(s->ctx,p,n) ? 1 : 0; }
extern "C" int d2_cancel_requested(const volatile uint32_t* flag) { return (flag && *flag) ? 1 : 0; }
extern "C" int d2_sse_emit_event(D2SseSink* s, const char* event_name, const char* data, uint32_t data_len) {
    if (!s || !s->ctx || !s->write_bytes || !event_name || !*event_name || (!data && data_len)) return 0;
    if (d2_cancel_requested(s->cancel_flag)) return 0;
    const char* a="event: "; const char* b="\ndata: "; const char* z="\n\n";
    if (!wr(s,a,7)) return 0;
    if (!wr(s,event_name,(uint32_t)strlen(event_name))) return 0;
    if (!wr(s,b,7)) return 0;
    if (data_len && !wr(s,data,data_len)) return 0;
    return wr(s,z,2);
}
extern "C" int d2_sse_emit_done(D2SseSink* s) {
    static const char done[]="[DONE]";
    return d2_sse_emit_event(s,"done",done,6);
}
