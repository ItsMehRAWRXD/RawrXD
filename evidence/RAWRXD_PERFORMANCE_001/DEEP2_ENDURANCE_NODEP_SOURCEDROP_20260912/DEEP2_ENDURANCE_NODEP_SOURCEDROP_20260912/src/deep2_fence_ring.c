#include "deep2_endurance.h"
#include <string.h>
int d2_fence_init(D2FenceRing *r,D2FenceSlot *s,size_t n){if(!r||!s||!n)return D2_EINVAL;memset(s,0,n*sizeof *s);r->slots=s;r->n=n;r->next_serial=1;return D2_OK;}
int d2_fence_acquire(D2FenceRing *r,size_t *slot,uint64_t *serial){size_t i;if(!r||!slot||!serial)return D2_EINVAL;for(i=0;i<r->n;i++)if(r->slots[i].state==D2_SLOT_FREE){r->slots[i].state=D2_SLOT_SUBMITTED;r->slots[i].serial=r->next_serial++;*slot=i;*serial=r->slots[i].serial;return D2_OK;}return D2_ECAP;}
int d2_fence_signal(D2FenceRing *r,size_t s,uint64_t ser){if(!r||s>=r->n)return D2_EINVAL;if(r->slots[s].state!=D2_SLOT_SUBMITTED||r->slots[s].serial!=ser)return D2_ESTATE;r->slots[s].state=D2_SLOT_SIGNALED;return D2_OK;}
int d2_fence_recycle(D2FenceRing *r,size_t s,uint64_t ser){if(!r||s>=r->n)return D2_EINVAL;if(r->slots[s].state!=D2_SLOT_SIGNALED||r->slots[s].serial!=ser)return D2_ESTATE;r->slots[s].state=D2_SLOT_FREE;return D2_OK;}
