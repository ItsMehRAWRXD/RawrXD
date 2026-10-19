#include "Deep2DeepSeekRuntime.hpp"

namespace Deep2 { namespace dsv3 {
bool PreserveRoute(const int32_t*ids,const float*w,const uint64_t*b,uint32_t n,Route&o){
    if(!ids||!w||!n||n>MAX_TOPK) return false; o.n=n;
    for(uint32_t i=0;i<n;++i){
        if(ids[i]<0) return false;
        o.x[i].id=ids[i]; o.x[i].weight=w[i]; o.x[i].bytes=b?b[i]:0;
        o.x[i].resident=0; o.x[i].stick=0;
    }
    return true;
}
static ExpertStat* Stat(State&s,uint32_t l,int e){
    for(uint32_t i=0;i<s.used;++i) if(s.stats[i].layer==l&&s.stats[i].expert==(uint32_t)e)
        return &s.stats[i];
    if(s.used>=State::STAT_CAP) return &s.stats[(l*257u+(uint32_t)e)%State::STAT_CAP];
    ExpertStat*p=&s.stats[s.used++]; *p=ExpertStat{}; p->layer=l;p->expert=(uint32_t)e; return p;
}
void ObserveExpert(State&s,uint32_t l,int e,unsigned g,uint64_t ns,int hit){
    ExpertStat*p=Stat(s,l,e); g&=1u; p->lastTick=s.tick; if(hit)p->hits++;else p->misses++;
    p->meanNs[g]=p->meanNs[g]?(p->meanNs[g]*7+ns)/8:ns;
    uint64_t den=p->hits+p->misses; p->heatPpm=den?(uint32_t)(p->hits*1000000ull/den):0;
    p->confidencePpm=den>=32?1000000u:(uint32_t)(den*31250u);
}
}} 
