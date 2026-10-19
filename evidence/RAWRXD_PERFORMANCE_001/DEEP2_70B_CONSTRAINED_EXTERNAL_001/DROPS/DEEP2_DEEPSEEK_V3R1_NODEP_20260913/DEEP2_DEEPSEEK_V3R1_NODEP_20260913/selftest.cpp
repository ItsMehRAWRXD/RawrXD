#include "Deep2DeepSeekRuntime.hpp"
#include "Deep2DeepSeekRuntime_Prefetch.hpp"
#include "Deep2DeepSeekDualStickAdapter.hpp"
#include <cstdio>
using namespace Deep2::dsv3;
static uint64_t cost(unsigned g,int resident,uint64_t b){return 10+g*3+(resident?0:b/1024);}
static unsigned assign(int pref,uint64_t b,int hit){if(hit&&pref>=0)return (unsigned)pref;return b&1u;}
static int resident(int l,int e,unsigned*s){(void)l;if((e&3)==0){*s=(unsigned)(e&1);return 1;}return 0;}
static int prefetch(int,int,unsigned){return 1;}
int main(){
    Config c{61,256,8,1,7168,2048,131072,512}; if(!ValidateConfig(c))return 10;
    DualStickCtx d{{cost,assign,resident,prefetch}}; State s{}; Init(s,c,MakeDualStickHooks(d)); BeginToken(s);
    int32_t ids[8]={1,2,3,4,5,6,7,8}; float w[8]={.2f,.18f,.16f,.14f,.12f,.1f,.06f,.04f};
    uint64_t b[8]={100,101,102,103,104,105,106,107}; Route r{}; if(!PreserveRoute(ids,w,b,8,r))return 11;
    BeginLayer(s); AssignRoute(s,3,r); if(s.metrics.selected!=8)return 12;
    for(unsigned i=0;i<8;++i){if(r.x[i].id!=ids[i]||r.x[i].weight!=w[i])return 13;
        ObserveExpert(s,3,r.x[i].id,r.x[i].stick,100+i*10,r.x[i].resident);}
    for(int k=0;k<40;++k)ObserveExpert(s,3,9,0,90,1);
    int32_t pf[8]{}; uint32_t pn=PlanPrefetch(s,3,r,pf,8); if(!pn)return 14;
    auto kv=PlanKv(100000,8192,32768); if(kv.hotTier!=TIER_VRAM||kv.coldTier!=TIER_MMAP)return 15;
    auto pp=PlanPrefill(s,4097); if(pp.chunks!=9)return 16;
    auto mtp=PlanMtp(20,4,4,true); if(!mtp.enabled||mtp.draftTokens!=4)return 17;
    if(QuantPolicy(900000,0)!=Q_HIGH)return 18;
    FinishToken(s,1000,100,0);
    std::puts("DEEP2_DEEPSEEK_V3R1_SELFTEST=PASS");
    std::puts("ROUTER_ID_WEIGHT_PARITY=PASS TOP15_SOURCE_READY=1 PRODUCT_BOUND=0 PROMOTE=0");
    return 0;
}
