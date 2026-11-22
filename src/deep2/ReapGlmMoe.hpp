#pragma once
#include "ReapExpertCompute.hpp"
#include <limits>
namespace Deep2 { namespace ReapQuant {
// GLM ungrouped softmax profile; grouped architectures require a different router.
template<class RoutedResolver,class SharedResolver>
bool ExecuteGlmMoe(const std::vector<float>& x,const std::vector<double>& logits,
 const std::vector<uint32_t>& retained,size_t topK,double scale,size_t sharedCount,
 RoutedResolver&& routed,SharedResolver&& shared,std::vector<float>& out){
    std::vector<RouteChoice> routes;
    if(!sharedCount||!RouteRetained(logits,retained,{},RouterScore::Softmax,
       topK,true,scale,routes))return false;
    std::vector<float> y;
    if(!ExecuteRoutedExperts(routes,x,routed,y))return false;
    std::vector<double> sum(y.begin(),y.end());
    for(size_t i=0;i<sharedCount;++i){
        SwiGluExpert e;
        if(!shared(i,e)||!ExecuteExpert(e,x,y)||y.size()!=sum.size())return false;
        for(size_t j=0;j<sum.size();++j)sum[j]+=y[j];
    }
    for(size_t j=0;j<sum.size();++j){
        if(!std::isfinite(sum[j])||std::abs(sum[j])>std::numeric_limits<float>::max())return false;
        y[j]=float(sum[j]);
    }
    out.swap(y);return true;
}
} }
