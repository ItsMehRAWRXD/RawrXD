#include "deep2_nostream.h"
static void zslots(d2ns_slot*p,uint64_t n){uint64_t i;for(i=0;i<n;i++){d2ns_slot z={0};p[i]=z;}}
size_t d2ns_slots_bytes(uint32_t l,uint32_t e){
 if(!l||!e||l>SIZE_MAX/e) return 0;
 size_t n=(size_t)l*e;
 return n>SIZE_MAX/sizeof(d2ns_slot)?0:n*sizeof(d2ns_slot);
}
int d2ns_init(d2ns_ctx*c,uint32_t l,uint32_t e,uint32_t k,uint32_t f,uint64_t b,const d2ns_cb*cb,void*a,size_t ab){
 size_t need=d2ns_slots_bytes(l,e); if(!c||!cb||!a||!need||ab<need||!b||!k||k>D2NS_MAX_TOPK||k>e) return D2NS_E_ARG;
 if(!cb->measure||!cb->load||!cb->release) return D2NS_E_ARG;
 c->moe_layers=l;c->experts_per_layer=e;c->top_k=k;c->flags=f;c->phase=D2NS_PHASE_PROMPT;c->prompt_tokens=0;
 c->budget=b;c->resident_bytes=0;c->loads=0;c->hits=0;c->misses=0;c->sync_loads=0;c->background_submits=0;
 c->cb=*cb;c->slots=(d2ns_slot*)a;c->slot_count=(uint64_t)l*e;zslots(c->slots,c->slot_count);return D2NS_OK;
}
int d2ns_require_object(d2ns_ctx*c,uint64_t id,uint32_t tok,uint64_t*out){
 uint64_t need=0,actual=0,h=0;int rc;d2ns_slot*s;if(!c||!out||id>=c->slot_count) return D2NS_E_RANGE;
 s=&c->slots[id];s->hits++;s->last_token=tok;if(s->resident){c->hits++;*out=s->handle;return D2NS_OK;}c->misses++;
 if(c->phase==D2NS_PHASE_DECODE&&(c->flags&D2NS_F_STRICT_PROMPT)&&!s->prompt_seen) return D2NS_E_STRICT_MISS;
 rc=c->cb.measure(c->cb.user,id,&need);if(rc||!need) return D2NS_E_LOAD;
 if(need>c->budget-c->resident_bytes) return D2NS_E_BUDGET;
 rc=c->cb.load(c->cb.user,id,need,&h,&actual);c->sync_loads++;if(rc||!h) return D2NS_E_LOAD;
 if(actual!=need){c->cb.release(c->cb.user,id,h);return D2NS_E_SIZE;}
 s->handle=h;s->bytes=actual;s->resident=1;if(c->phase==D2NS_PHASE_PROMPT){s->prompt_seen=1;if(c->flags&D2NS_F_PIN_PROMPT)s->pinned=1;}
 c->resident_bytes+=actual;c->loads++;*out=h;return D2NS_OK;
}
int d2ns_require_route(d2ns_ctx*c,uint32_t tok,uint32_t layer,const uint32_t*ids,uint32_t n,d2ns_route*out){
 uint32_t i,j,ln=0;int rc;if(!c||!ids||!out||layer>=c->moe_layers||n!=c->top_k) return D2NS_E_ARG;
 out->count=0;out->loaded_now=0;for(i=0;i<n;i++){if(ids[i]>=c->experts_per_layer)return D2NS_E_RANGE;for(j=0;j<i;j++)if(ids[i]==ids[j])return D2NS_E_DUP;}
 for(i=0;i<n;i++){uint64_t id=(uint64_t)layer*c->experts_per_layer+ids[i],before=c->loads;
  rc=d2ns_require_object(c,id,tok,&out->handles[i]);if(rc){c->phase=D2NS_PHASE_FAILED;return rc;}ln+=(c->loads!=before);out->count++;}
 out->loaded_now=ln;return D2NS_OK;
}
int d2ns_seal_prompt(d2ns_ctx*c,uint32_t n){if(!c||c->phase!=D2NS_PHASE_PROMPT||!n)return D2NS_E_ARG;c->prompt_tokens=n;c->phase=D2NS_PHASE_DECODE;return 0;}
void d2ns_release_object(d2ns_ctx*c,uint64_t id){d2ns_slot*s;if(!c||id>=c->slot_count)return;s=&c->slots[id];if(!s->resident||s->pinned)return;c->cb.release(c->cb.user,id,s->handle);c->resident_bytes-=s->bytes;s->resident=0;s->handle=0;s->bytes=0;}
void d2ns_release_all(d2ns_ctx*c){uint64_t i;if(!c)return;for(i=0;i<c->slot_count;i++){d2ns_slot*s=&c->slots[i];if(s->resident)c->cb.release(c->cb.user,i,s->handle);s->resident=0;s->handle=0;s->bytes=0;}c->resident_bytes=0;}
