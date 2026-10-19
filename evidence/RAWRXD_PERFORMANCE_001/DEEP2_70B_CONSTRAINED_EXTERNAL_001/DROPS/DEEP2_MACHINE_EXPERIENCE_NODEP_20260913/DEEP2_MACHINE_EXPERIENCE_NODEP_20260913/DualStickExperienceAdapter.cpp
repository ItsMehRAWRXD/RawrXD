#include "DualStickExperienceAdapter.hpp"

namespace Deep2 {
static mx::Key K(uint32_t l,int e,unsigned g,uint32_t q,uint32_t inD,uint32_t outD,int r){
    mx::Key k{}; k.layer=(uint16_t)l; k.expert=(uint16_t)(e<0?0:e); k.gpu=(uint8_t)(g&1u);
    k.quant=(uint8_t)q; k.inBucket=(uint16_t)(inD>>6); k.outBucket=(uint16_t)(outD>>6);
    k.residency=(uint8_t)(r?1:0); k.kernel=0;
    k.featureMask=mx::F_KERNEL|mx::F_RESIDENCY|mx::F_AFFINITY;
    return k;
}
void DualStickExperienceInit(DualStickExperience&x,const mx::Epoch&e,const mx::Regime&r){
    x.epoch=e; x.regime=r; x.tick=0; mx::Init(x.store,e,r);
}
uint64_t DualStickExperienceCost(DualStickExperience&x,uint32_t l,int e,unsigned g,
                                 uint32_t q,uint32_t inD,uint32_t outD,int r,
                                 uint64_t fallback,uint32_t*conf){
    mx::Prediction p=mx::Predict(x.store,K(l,e,g,q,inD,outD,r),++x.tick,fallback);
    if(conf)*conf=p.confidencePpm; return p.ns;
}
void DualStickExperienceObserve(DualStickExperience&x,uint32_t l,int e,unsigned g,
                                uint32_t q,uint32_t inD,uint32_t outD,int r,
                                uint64_t actual,uint64_t pred,bool truth){
    mx::Observe(x.store,K(l,e,g,q,inD,outD,r),actual,pred,++x.tick,truth);
}
}
