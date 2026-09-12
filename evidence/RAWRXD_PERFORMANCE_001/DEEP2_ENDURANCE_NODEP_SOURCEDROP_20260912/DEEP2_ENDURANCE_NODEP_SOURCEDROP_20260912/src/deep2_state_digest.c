#include "deep2_endurance.h"
uint64_t d2_hash64(const void *d,size_t n,uint64_t h){const unsigned char *p=(const unsigned char*)d;size_t i;if(!h)h=UINT64_C(1469598103934665603);for(i=0;i<n;i++){h^=p[i];h*=UINT64_C(1099511628211);}return h;}
uint64_t d2_state_digest(uint64_t t,uint64_t p,uint64_t e,uint64_t f,uint64_t c,uint64_t r){uint64_t v[6]={t,p,e,f,c,r};return d2_hash64(v,sizeof v,0);}
