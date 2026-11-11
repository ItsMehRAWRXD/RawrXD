#pragma once
#include "Deep2B46NativeQuant.hpp"
#include "Deep2B47RegisterExpert.hpp"
#include "Deep2B48CrossLayerFusion.hpp"
#include "Deep2B49ShaderSpecializer.hpp"
#include "Deep2B50ChallengeSeal.hpp"

namespace Deep2 {

struct B46_50BackendOps {
    void* user=nullptr;
    bool (*applyNativeQuant)(void*,const B46NativeQuantPlan&)=nullptr;
    bool (*applyRegisterExpert)(void*,const B47RegisterExpertPlan&)=nullptr;
    bool (*applyCrossLayerFusion)(void*,const B48FusionPlan&)=nullptr;
    bool (*applyShaderKey)(void*,const B49ShaderKey&)=nullptr;
};

inline bool ApplyB46_50(B46_50BackendOps& o,
                        const B46NativeQuantPlan& a,
                        const B47RegisterExpertPlan& b,
                        const B48FusionPlan& c,
                        const B49ShaderKey& d) {
    if(o.applyNativeQuant && !o.applyNativeQuant(o.user,a)) return false;
    if(o.applyRegisterExpert && !o.applyRegisterExpert(o.user,b)) return false;
    if(o.applyCrossLayerFusion && !o.applyCrossLayerFusion(o.user,c)) return false;
    if(o.applyShaderKey && !o.applyShaderKey(o.user,d)) return false;
    return true;
}

}
