#ifndef D2_STREAM_H
#define D2_STREAM_H
#include "d2_common.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum D2StreamState { D2_STREAM_FREE=0,D2_STREAM_QUEUED=1,D2_STREAM_INFLIGHT=2,D2_STREAM_DONE=3,D2_STREAM_FAILED=4 } D2StreamState;
typedef struct D2StreamReq {
    uint64_t ticket;
    D2ByteRange range;
    uint32_t device;
    uint32_t state;
} D2StreamReq;
typedef struct D2StreamQueue {
    D2StreamReq item[D2_STREAM_CAP];
    uint32_t head,tail,count;
    uint64_t next_ticket;
    D2ObservedCounters *counters;
} D2StreamQueue;
void d2_stream_init(D2StreamQueue *q,D2ObservedCounters *c);
int d2_stream_push(D2StreamQueue *q,const D2ByteRange *r,uint32_t device,uint64_t *ticket);
int d2_stream_pop(D2StreamQueue *q,D2StreamReq *out);
int d2_stream_complete(D2StreamReq *r,int io_rc);
#ifdef __cplusplus
}
#endif
#endif
