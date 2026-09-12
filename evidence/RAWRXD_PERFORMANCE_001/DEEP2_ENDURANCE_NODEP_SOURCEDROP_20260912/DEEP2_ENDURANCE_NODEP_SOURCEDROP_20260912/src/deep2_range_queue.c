#include "deep2_endurance.h"
#include <string.h>
int d2_rq_init(D2RangeQueue *q,D2RangeReq *i,size_t c){if(!q||!i||!c)return D2_EINVAL;memset(q,0,sizeof *q);q->items=i;q->cap=c;return D2_OK;}
int d2_rq_push(D2RangeQueue *q,const D2RangeReq *r){if(!q||!r||r->end<=r->begin)return D2_EINVAL;if(q->count==q->cap)return D2_ECAP;q->items[q->tail]=*r;q->tail=(q->tail+1)%q->cap;q->count++;return D2_OK;}
int d2_rq_pop(D2RangeQueue *q,D2RangeReq *o){if(!q||!o)return D2_EINVAL;if(!q->count)return D2_ESTATE;*o=q->items[q->head];q->head=(q->head+1)%q->cap;q->count--;return D2_OK;}
