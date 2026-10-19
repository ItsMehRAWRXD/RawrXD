#include "Deep2MachineExperience.hpp"
#include <cstring>

namespace Deep2 { namespace mx {
static bool Eq(const Key&a,const Key&b){ return std::memcmp(&a,&b,sizeof(Key))==0; }
static Cell* Find(Store&s,const Key&k){
    for(uint32_t i=0;i<s.used;++i) if(Eq(s.cells[i].key,k)) return &s.cells[i];
    if(s.used<Store::CAP){ Cell*c=&s.cells[s.used++]; std::memset(c,0,sizeof(*c)); c->key=k; return c; }
    uint32_t ev=0; for(uint32_t i=1;i<s.used;++i) if(s.cells[i].lastTick<s.cells[ev].lastTick) ev=i;
    Cell*c=&s.cells[ev]; std::memset(c,0,sizeof(*c)); c->key=k; return c;
}
void Observe(Store&s,const Key&k,uint64_t actual,uint64_t predicted,uint64_t tick,bool truth){
    if(!actual) return; Cell*c=Find(s,k);
    uint64_t old=c->meanNs; c->samples++;
    uint32_t alpha = c->samples<4?500000u:125000u;
    if(predicted){
        uint64_t d=actual>predicted?actual-predicted:predicted-actual;
        uint64_t ppm=(d*1000000ull)/predicted; if(ppm>1000000ull) ppm=1000000ull;
        c->driftPpm=(uint32_t)ppm;
        if(ppm>250000ull) alpha=500000u;
    }
    c->meanNs = old ? (old*(1000000u-alpha)+actual*alpha)/1000000u : actual;
    uint64_t dev=actual>c->meanNs?actual-c->meanNs:c->meanNs-actual;
    c->devNs = c->devNs ? (c->devNs*7+dev)/8 : dev;
    c->lastTick=tick; c->epochHash=s.epochHash; c->regimeHash=s.regimeHash;
    c->generation=s.generation; c->flags|=C_VALID|C_LIVE;
    if(truth) c->flags|=C_TRUTH;
    if(truth && c->driftPpm<100000u) c->flags&=~C_QUARANTINE;
}
void QuarantineDrift(Store&s,uint32_t trip){
    for(uint32_t i=0;i<s.used;++i) if(s.cells[i].driftPpm>trip) s.cells[i].flags|=C_QUARANTINE;
}
void Revalidate(Store&s,const Key&k,uint64_t actual,uint32_t tol){
    for(uint32_t i=0;i<s.used;++i) if(Eq(s.cells[i].key,k)){
        Cell&c=s.cells[i]; if(!c.meanNs||!actual) return;
        uint64_t d=actual>c.meanNs?actual-c.meanNs:c.meanNs-actual;
        uint64_t ppm=(d*1000000ull)/c.meanNs;
        if(ppm<=tol){ c.flags&=~C_QUARANTINE; c.flags|=C_TRUTH; } else c.flags|=C_QUARANTINE;
        return;
    }
}
}}
