#include "Deep2DeepSeekRuntime.hpp"

namespace Deep2 { namespace dsv3 {
MtpPlan PlanMtp(uint32_t remaining,uint32_t maxDraft,uint32_t verify,bool supported){
    MtpPlan p{}; p.enabled=supported?1:0; if(!p.enabled)return p;
    p.draftTokens=remaining<maxDraft?remaining:maxDraft; p.verifyBatch=verify?verify:1u;
    if(p.verifyBatch>p.draftTokens)p.verifyBatch=p.draftTokens; return p;
}
QuantClass QuantPolicy(uint32_t sensitivity,uint32_t outlier){
    if(sensitivity>=800000u||outlier>=500000u)return Q_HIGH;
    if(sensitivity>=400000u||outlier>=200000u)return Q_SAFE;
    return Q_LOW;
}
}} 
