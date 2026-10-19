#include "deep2_nostream.h"
#include "deepseek2_671b_profile.h"
#include <stdlib.h>
#include <stdio.h>
typedef struct{uint64_t next;}S;
static int m(void*u,uint64_t id,uint64_t*b){(void)u;(void)id;*b=4096;return 0;}
static int l(void*u,uint64_t id,uint64_t e,uint64_t*h,uint64_t*a){S*s=(S*)u;(void)id;*h=++s->next;*a=e;return 0;}
static void r(void*u,uint64_t id,uint64_t h){(void)u;(void)id;(void)h;}
int main(void){d2ns_ctx c;d2ns_cb cb;d2ns_route rr;S s={100};uint32_t ids[8]={1,2,3,4,5,6,7,8};size_t n;void*a;int rc;
 if(DS2_MOE_BLOCKS!=58||DS2_EXPERT_COUNT!=256||DS2_EXPERT_USED_COUNT!=8)return 1;
 n=d2ns_slots_bytes(DS2_MOE_BLOCKS,DS2_EXPERT_COUNT);a=malloc(n);if(!a)return 2;
 cb.measure=m;cb.load=l;cb.release=r;cb.user=&s;
 rc=d2ns_init(&c,DS2_MOE_BLOCKS,DS2_EXPERT_COUNT,DS2_EXPERT_USED_COUNT,D2NS_F_PIN_PROMPT,64ull<<20,&cb,a,n);if(rc)return 3;
 rc=d2ns_require_route(&c,0,0,ids,8,&rr);if(rc||rr.loaded_now!=8)return 4;
 rc=d2ns_require_route(&c,1,0,ids,8,&rr);if(rc||rr.loaded_now!=0)return 5;
 if(c.background_submits!=0||c.sync_loads!=8)return 6;
 rc=d2ns_seal_prompt(&c,2);if(rc)return 7;ids[0]=9;rc=d2ns_require_route(&c,2,0,ids,8,&rr);if(rc)return 8;
 if(c.background_submits!=0||c.sync_loads!=9)return 9;
 d2ns_release_all(&c);free(a);
 puts("DEEP2_NOSTREAM_PORTABLE_SMOKE=PASS");return 0;}
