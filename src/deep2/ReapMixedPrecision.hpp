#include <utility>
#pragma once
#include "ReapQ3KCodec.hpp"
#include <vector>
#include <unordered_set>

namespace Deep2 { namespace ReapQuant {
enum class Precision : unsigned { Q2=0,Q3=1,Q4=2 };
struct ExpertCost {
    uint64_t id=0, blocks=0;
    double importance=1, squaredQ2=0, squaredQ3=0;
};
struct ExpertChoice { uint64_t id=0, bytes=0; Precision precision=Precision::Q2; };
struct MixedPlan { std::vector<ExpertChoice> choices; uint64_t bytes=0; double weightedError=0; };
// Budget is the retained expert payload budget, excluding fixed model tensors.
// Greedy benefit/byte allocation; no claim of global knapsack optimality.
inline bool PlanMixed(const std::vector<ExpertCost>& costs,uint64_t budget,MixedPlan& out) {
    if(costs.empty())return false;
    MixedPlan next;
    std::unordered_set<uint64_t> ids;
    auto loss=[](const ExpertCost& c,Precision p){
        return c.importance*(p==Precision::Q2?c.squaredQ2:p==Precision::Q3?c.squaredQ3:0.0);
    };
    for(const auto& c:costs){
        if(!ids.insert(c.id).second||!c.blocks||c.blocks>UINT64_MAX/Q4Bytes||
           !std::isfinite(c.importance)||c.importance<0||
           !std::isfinite(c.squaredQ2)||c.squaredQ2<0||
           !std::isfinite(c.squaredQ3)||c.squaredQ3<0||
           !std::isfinite(loss(c,Precision::Q2))||!std::isfinite(loss(c,Precision::Q3)))return false;
        const auto bytes=c.blocks*Q2Bytes;
        if(bytes>budget-next.bytes)return false;
        next.bytes+=bytes;
        next.choices.push_back({c.id,bytes,Precision::Q2});
    }
    for(;;){
        size_t best=costs.size();Precision target=Precision::Q4;
        uint64_t extra=0;double score=0;
        for(size_t i=0;i<costs.size();++i){
            const auto& c=costs[i];const auto& cur=next.choices[i];
            for(auto p:{Precision::Q3,Precision::Q4}){
                if(unsigned(p)<=unsigned(cur.precision))continue;
                const auto bytes=c.blocks*(p==Precision::Q3?Q3Bytes:Q4Bytes);
                const auto delta=bytes-cur.bytes;
                if(delta>budget-next.bytes)continue;
                const double gain=loss(c,cur.precision)-loss(c,p);
                const double ratio=gain/double(delta);
                if(ratio>score||(ratio==score&&ratio>0&&best<costs.size()&&c.id<costs[best].id)){
                    best=i;target=p;extra=delta;score=ratio;
                }
            }
        }
        if(best==costs.size())break;
        next.choices[best].precision=target;
        next.choices[best].bytes+=extra;next.bytes+=extra;
    }
    for(size_t i=0;i<costs.size();++i)next.weightedError+=loss(costs[i],next.choices[i].precision);
    if(!std::isfinite(next.weightedError))return false;
    out=std::move(next);return true;
}
} }
