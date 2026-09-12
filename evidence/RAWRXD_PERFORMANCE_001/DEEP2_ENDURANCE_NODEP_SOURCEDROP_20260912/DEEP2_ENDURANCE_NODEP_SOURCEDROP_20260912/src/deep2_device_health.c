#include "deep2_endurance.h"
#include <string.h>
#include <stdio.h>
void d2_health_init(D2DeviceHealth *h){if(h)memset(h,0,sizeof *h);}
void d2_health_submit(D2DeviceHealth *h,uint64_t s){if(h&&s>h->submit_serial)h->submit_serial=s;}
void d2_health_complete(D2DeviceHealth *h,uint64_t s,int r,const char *o){if(!h)return;if(s>h->complete_serial)h->complete_serial=s;h->last_result=r;if(o)snprintf(h->owner,sizeof h->owner,"%s",o);if(r<0)h->device_lost=1;}
int d2_health_check(const D2DeviceHealth *h){if(!h)return D2_EINVAL;if(h->device_lost)return D2_ESTATE;if(h->complete_serial>h->submit_serial)return D2_ECORRUPT;return D2_OK;}
