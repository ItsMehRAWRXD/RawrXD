#include "d2_stream.h"
#include "d2_range.h"
#include <string.h>
void d2_stream_init(D2StreamQueue *q,D2ObservedCounters *c){if(!q)return;memset(q,0,sizeof(*q));q->next_ticket=1;q->counters=c;}
int d2_stream_push(D2StreamQueue *q,const D2ByteRange *r,uint32_t d,uint64_t *t){D2StreamReq *x;if(!q||!r||d>=2||!d2_range_valid(r))return D2_EINVAL;if(q->count>=D2_STREAM_CAP)return D2_ENOSPC;x=&q->item[q->tail];memset(x,0,sizeof(*x));x->ticket=q->next_ticket++;x->range=*r;x->device=d;x->state=D2_STREAM_QUEUED;q->tail=(q->tail+1)%D2_STREAM_CAP;q->count++;if(q->counters){q->counters->queue_push++;q->counters->exact_range_requests++;q->counters->exact_range_bytes+=r->bytes;}if(t)*t=x->ticket;return D2_OK;}
int d2_stream_pop(D2StreamQueue *q,D2StreamReq *out){D2StreamReq *x;if(!q||!out)return D2_EINVAL;if(!q->count)return D2_ENOTFOUND;x=&q->item[q->head];if(x->state!=D2_STREAM_QUEUED)return D2_ESTATE;*out=*x;out->state=D2_STREAM_INFLIGHT;memset(x,0,sizeof(*x));q->head=(q->head+1)%D2_STREAM_CAP;q->count--;if(q->counters)q->counters->queue_pop++;return D2_OK;}
int d2_stream_complete(D2StreamReq *r,int rc){if(!r||r->state!=D2_STREAM_INFLIGHT)return D2_ESTATE;r->state=rc==D2_OK?D2_STREAM_DONE:D2_STREAM_FAILED;return rc;}
