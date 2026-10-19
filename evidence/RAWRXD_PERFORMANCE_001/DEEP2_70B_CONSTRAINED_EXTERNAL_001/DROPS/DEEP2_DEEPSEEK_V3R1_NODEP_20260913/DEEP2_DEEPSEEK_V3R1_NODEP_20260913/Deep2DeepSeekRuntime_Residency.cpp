#include "Deep2DeepSeekRuntime.hpp"

namespace Deep2 { namespace dsv3 {
uint64_t ScoreResidency(const ExpertStat&st,uint64_t bytes,uint64_t reloadNs){
    if(!bytes) bytes=1; uint64_t reuse=(uint64_t)st.heatPpm+st.confidencePpm/4u;
    uint64_t save=(reloadNs/1000ull+1ull)*(reuse+1ull);
    return save/(bytes>>20?bytes>>20:1ull);
}
uint32_t PlanPrefetch(State&s,uint32_t layer,const Route&r,int32_t*out,uint32_t cap){
    if(!out||!cap) return 0; uint32_t n=0;
    for(uint32_t i=0;i<s.used&&n<cap;++i){
        ExpertStat&st=s.stats[i]; if(st.layer!=layer||st.heatPpm<500000u) continue;
        bool selected=false; for(uint32_t j=0;j<r.n;++j) if(r.x[j].id==(int32_t)st.expert) selected=true;
        if(!selected) out[n++]=(int32_t)st.expert;
    }
    s.metrics.prefetches+=n; return n;
}
}} 
