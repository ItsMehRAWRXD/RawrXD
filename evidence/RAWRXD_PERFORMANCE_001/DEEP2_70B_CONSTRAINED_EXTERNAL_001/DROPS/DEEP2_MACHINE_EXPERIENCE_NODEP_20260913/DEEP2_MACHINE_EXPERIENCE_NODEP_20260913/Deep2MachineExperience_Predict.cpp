#include "Deep2MachineExperience.hpp"
#include <cstring>

namespace Deep2 { namespace mx {
static bool Eq(const Key&a,const Key&b){ return std::memcmp(&a,&b,sizeof(Key))==0; }
static uint32_t Confidence(const Cell&c,uint64_t tick){
    uint64_t age=tick>c.lastTick?tick-c.lastTick:0;
    uint32_t sample = c.samples>=32?1000000u:c.samples*31250u;
    uint32_t var = c.meanNs ? (uint32_t)((c.devNs*1000000ull)/c.meanNs) : 1000000u;
    if(var>1000000u) var=1000000u;
    uint32_t agePen=(uint32_t)(age>1000?1000000u:age*1000u);
    uint64_t q=(uint64_t)sample*(1000000u-var)/1000000u;
    q=q*(1000000u-agePen)/1000000u; return (uint32_t)q;
}
Prediction Predict(const Store&s,const Key&k,uint64_t tick,uint64_t fallback){
    const Cell* exact=nullptr; const Cell* near=nullptr; uint32_t best=0xffffffffu;
    for(uint32_t i=0;i<s.used;++i){
        const Cell&c=s.cells[i]; if(!(c.flags&C_VALID)) continue;
        if(Eq(c.key,k)){ exact=&c; break; }
        if(c.key.gpu==k.gpu && c.key.quant==k.quant && c.key.inBucket==k.inBucket &&
           c.key.outBucket==k.outBucket && !(c.flags&C_QUARANTINE)){
            uint32_t d=(c.key.layer>k.layer?c.key.layer-k.layer:k.layer-c.key.layer)+
                       (c.key.expert>k.expert?c.key.expert-k.expert:k.expert-c.key.expert);
            if(d<best){best=d;near=&c;}
        }
    }
    const Cell*c=exact?exact:near; Prediction p{fallback,0,1000000u,SRC_DEFAULT,0};
    if(!c) return p; uint32_t conf=Confidence(*c,tick);
    uint32_t stale=c->driftPpm; if(c->epochHash!=s.epochHash) stale+=400000u;
    if(c->regimeHash!=s.regimeHash) stale+=200000u; if(stale>1000000u) stale=1000000u;
    p.ns=c->meanNs; p.confidencePpm=conf; p.staleRiskPpm=stale;
    p.quarantined=(c->flags&C_QUARANTINE)?1:0;
    p.source=(c->flags&C_LIVE)?SRC_LIVE:(exact?SRC_HISTORY:SRC_NEAREST);
    if(p.quarantined || conf<50000u){ p.ns=fallback; p.source=SRC_DEFAULT; }
    return p;
}
}}
