#pragma once
#include <vector>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>
namespace Deep2 { namespace ReapQuant {
enum class RouterScore { Softmax, Sigmoid };
struct RouteChoice { uint32_t original, retained; double weight; };
// Ungrouped routing only. Bias affects ranking, never mixture weights.
// Softmax normalization uses the retained population.
inline bool RouteRetained(const std::vector<double>& logits,
 const std::vector<uint32_t>& retained, const std::vector<double>& bias,
 RouterScore mode,size_t k,bool normalize,double scale,
 std::vector<RouteChoice>& out) {
    if(logits.empty()||retained.empty()||retained.size()>UINT32_MAX||
       !k||k>retained.size()||(!bias.empty()&&bias.size()!=logits.size())||
       !std::isfinite(scale)||scale<=0||
       (mode!=RouterScore::Softmax&&mode!=RouterScore::Sigmoid))return false;
    std::vector<uint32_t> ids=retained;
    std::sort(ids.begin(),ids.end());
    if(ids.back()>=logits.size()||std::adjacent_find(ids.begin(),ids.end())!=ids.end())return false;
    double maxLogit=logits[ids.front()];
    for(auto id:ids){
        if(!std::isfinite(logits[id])||(!bias.empty()&&!std::isfinite(bias[id])))return false;
        maxLogit=std::max(maxLogit,logits[id]);
    }
    struct Candidate { RouteChoice route; double rank; };
    std::vector<Candidate> candidates;
    double sum=0;
    for(size_t i=0;i<retained.size();++i){
        auto id=retained[i];const double x=logits[id];
        const double w=mode==RouterScore::Softmax?std::exp(x-maxLogit):
            x>=0?1/(1+std::exp(-x)):std::exp(x)/(1+std::exp(x));
        sum+=w;candidates.push_back({{id,uint32_t(i),w},0});
    }
    if(mode==RouterScore::Softmax&&(!std::isfinite(sum)||sum<=0))return false;
    for(auto& c:candidates){
        if(mode==RouterScore::Softmax)c.route.weight/=sum;
        c.rank=c.route.weight+(bias.empty()?0:bias[c.route.original]);
        if(!std::isfinite(c.rank))return false;
    }
    std::sort(candidates.begin(),candidates.end(),[](const Candidate& a,const Candidate& b){
        return a.rank==b.rank?a.route.original<b.route.original:a.rank>b.rank;
    });
    sum=0;for(size_t i=0;i<k;++i)sum+=candidates[i].route.weight;
    if(normalize&&(!std::isfinite(sum)||sum<=0))return false;
    std::vector<RouteChoice> next;
    for(size_t i=0;i<k;++i){
        auto c=candidates[i].route;
        c.weight=(normalize?c.weight/sum:c.weight)*scale;
        if(!std::isfinite(c.weight))return false;
        next.push_back(c);
    }
    out=std::move(next);return true;
}
} }
