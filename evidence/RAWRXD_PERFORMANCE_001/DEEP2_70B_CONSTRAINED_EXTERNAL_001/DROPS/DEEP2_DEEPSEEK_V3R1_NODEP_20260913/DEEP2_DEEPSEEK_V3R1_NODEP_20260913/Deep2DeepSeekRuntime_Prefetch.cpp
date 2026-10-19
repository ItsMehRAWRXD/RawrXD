#include "Deep2DeepSeekRuntime.hpp"

namespace Deep2 { namespace dsv3 {
static int Contains(const Route&r,int e){for(uint32_t i=0;i<r.n;++i)if(r.x[i].id==e)return 1;return 0;}
uint32_t ExecutePrefetch(State&s,uint32_t layer,const Route&r,uint32_t maxN){
    if(!s.hooks.prefetch||!maxN)return 0; int32_t ids[MAX_PREFETCH];
    uint32_t cap=maxN<MAX_PREFETCH?maxN:MAX_PREFETCH; uint32_t n=PlanPrefetch(s,layer,r,ids,cap),done=0;
    for(uint32_t i=0;i<n;++i){ if(Contains(r,ids[i]))continue;
        unsigned g=(unsigned)(ids[i]&1); if(s.hooks.prefetch(s.hooks.ctx,layer,ids[i],g))done++; }
    return done;
}
}} 
