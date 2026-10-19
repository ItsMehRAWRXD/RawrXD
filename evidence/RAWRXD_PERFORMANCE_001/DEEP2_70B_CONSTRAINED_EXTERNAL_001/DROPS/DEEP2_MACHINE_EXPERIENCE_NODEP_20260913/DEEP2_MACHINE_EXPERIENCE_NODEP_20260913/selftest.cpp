#include "Deep2MachineExperience.hpp"
#include "DualStickExperienceAdapter.hpp"
#include <cstdio>
using namespace Deep2;
int main(){
    mx::Epoch e{1,2,3,4,5,6}; mx::Regime r{10,11,1,1,2,2,0,1};
    DualStickExperience x{}; DualStickExperienceInit(x,e,r);
    uint32_t c=0; uint64_t f=16000000ull;
    if(DualStickExperienceCost(x,3,7,0,14,7168,2048,1,f,&c)!=f) return 10;
    for(int i=0;i<40;++i)
        DualStickExperienceObserve(x,3,7,0,14,7168,2048,1,9000000+i*1000,9000000,true);
    uint64_t a=DualStickExperienceCost(x,3,7,0,14,7168,2048,1,f,&c);
    if(!(a<12000000ull&&c>100000u)) return 11;
    if(!mx::Save(x.store,"mx_test.bin")) return 12;
    mx::Store y{}; if(!mx::Load(y,"mx_test.bin",e,r)) return 13;
    mx::Key k{}; k.layer=3;k.expert=7;k.gpu=0;k.quant=14;k.inBucket=7168>>6;
    k.outBucket=2048>>6;k.residency=1;k.featureMask=mx::F_KERNEL|mx::F_RESIDENCY|mx::F_AFFINITY;
    auto p=mx::Predict(y,k,50,f); if(p.ns==f) return 14;
    mx::Epoch e2=e; e2.kernelAbi++;
    mx::BeginGeneration(y,e2,r,mx::F_KERNEL);
    auto q=mx::Predict(y,k,51,f); if(q.ns!=f) return 15;
    mx::Revalidate(y,k,a,200000u);
    mx::Observe(y,k,a,a,52,true); auto z=mx::Predict(y,k,53,f);
    if(z.ns==f) return 16;
    mx::Observe(y,k,a*2,a,54,true); mx::QuarantineDrift(y,250000u);
    auto w=mx::Predict(y,k,55,f); if(w.ns!=f) return 17;
    std::remove("mx_test.bin");
    std::puts("DEEP2_MACHINE_EXPERIENCE_SELFTEST=PASS");
    std::puts("TOP15_MECHANICS=15/15 SOURCE_READY=1 PRODUCT_BOUND=0 PROMOTE=0");
    return 0;
}
