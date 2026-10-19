#include "Deep2MachineExperience.hpp"
#include <cstring>

namespace Deep2 { namespace mx {
static uint64_t H(const void* p, size_t n) {
    const uint8_t* b=(const uint8_t*)p; uint64_t h=1469598103934665603ull;
    for(size_t i=0;i<n;++i){ h^=b[i]; h*=1099511628211ull; } return h;
}
uint64_t HashEpoch(const Epoch& e){ return H(&e,sizeof(e)); }
uint64_t HashRegime(const Regime& r){ return H(&r,sizeof(r)); }
uint32_t Checksum(const void* p,size_t n){
    const uint8_t* b=(const uint8_t*)p; uint32_t h=2166136261u;
    for(size_t i=0;i<n;++i){ h^=b[i]; h*=16777619u; } return h;
}
uint32_t RegimeDistancePpm(const Regime& a,const Regime& b){
    const uint16_t* x=(const uint16_t*)&a; const uint16_t* y=(const uint16_t*)&b;
    uint64_t num=0,den=0;
    for(size_t i=0;i<sizeof(Regime)/2;++i){
        num += x[i]>y[i]?x[i]-y[i]:y[i]-x[i]; den += x[i]>y[i]?x[i]:y[i];
    }
    if(!den) return 0; uint64_t ppm=(num*1000000ull)/den;
    return ppm>1000000ull?1000000u:(uint32_t)ppm;
}
void Init(Store& s,const Epoch& e,const Regime& r){
    std::memset(&s,0,sizeof(s)); s.generation=1;
    s.epochHash=HashEpoch(e); s.regimeHash=HashRegime(r);
}
void BeginGeneration(Store& s,const Epoch& e,const Regime& r,uint32_t changedMask){
    s.generation++; s.epochHash=HashEpoch(e); s.regimeHash=HashRegime(r);
    s.invalidMask=changedMask;
    for(uint32_t i=0;i<s.used;++i)
        if(s.cells[i].key.featureMask & changedMask) s.cells[i].flags|=C_QUARANTINE;
}
}} 
