#include "deep2_endurance.h"
#include <string.h>
int d2_desc_init(D2DescriptorRing *r,D2DescriptorSlot *s,size_t n){if(!r||!s||!n)return D2_EINVAL;memset(s,0,n*sizeof *s);r->slots=s;r->n=n;return D2_OK;}
int d2_desc_acquire(D2DescriptorRing *r,uint64_t g,size_t *slot){size_t i;if(!r||!g||!slot)return D2_EINVAL;for(i=0;i<r->n;i++)if(!r->slots[i].in_use){r->slots[i].in_use=1;r->slots[i].generation=g;*slot=i;return D2_OK;}return D2_ECAP;}
int d2_desc_release(D2DescriptorRing *r,size_t s,uint64_t g){if(!r||s>=r->n)return D2_EINVAL;if(!r->slots[s].in_use||r->slots[s].generation!=g)return D2_ESTATE;r->slots[s].in_use=0;return D2_OK;}
