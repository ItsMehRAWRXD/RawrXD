#include "Deep2DeepSeekRuntime.hpp"

namespace Deep2 { namespace dsv3 {
void AssignRoute(State&s,uint32_t layer,Route&r){
    for(uint32_t i=0;i<r.n;++i){
        RoutedExpert&x=r.x[i]; unsigned residentStick=0; int hit=0;
        if(s.hooks.resident) hit=s.hooks.resident(s.hooks.ctx,layer,x.id,&residentStick);
        x.resident=(uint8_t)(hit?1:0);
        unsigned pick=0;
        if(s.hooks.assign) pick=s.hooks.assign(s.hooks.ctx,hit?(int)residentStick:-1,x.bytes,hit);
        else if(s.hooks.cost){
            uint64_t c0=s.predictedFinish[0]+s.hooks.cost(s.hooks.ctx,0,hit?0:-1,x.bytes,hit);
            uint64_t c1=s.predictedFinish[1]+s.hooks.cost(s.hooks.ctx,1,hit?1:-1,x.bytes,hit);
            pick=c1<c0?1u:0u;
        } else pick=s.predictedFinish[1]<s.predictedFinish[0]?1u:0u;
        x.stick=(uint8_t)(pick&1u); s.metrics.selected++;
        uint64_t c=s.hooks.cost?s.hooks.cost(s.hooks.ctx,pick,hit?(int)pick:-1,x.bytes,hit):1;
        s.predictedFinish[pick&1u]+=c;
    }
}
}} 
