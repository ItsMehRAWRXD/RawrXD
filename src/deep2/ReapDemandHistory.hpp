#pragma once
#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <mutex>
#include <utility>
namespace Deep2 { namespace ReapQuant {
// One instance per model/layer. Observe actual selected expert IDs once per token.
class DemandHistory {
    std::mutex mutex_;
    std::vector<double> scores_;
    double decay_;
public:
    explicit DemandHistory(size_t experts,double decay=0.875):scores_(experts,0),decay_(decay>=0&&decay<1?decay:0.875){}
    bool Observe(const std::vector<uint32_t>& ids){
        std::lock_guard<std::mutex> lock(mutex_);
        auto sorted=ids;std::sort(sorted.begin(),sorted.end());
        if(sorted.empty()||sorted.back()>=scores_.size()||std::adjacent_find(sorted.begin(),sorted.end())!=sorted.end())return false;
        for(auto& s:scores_)s*=decay_;
        for(auto id:sorted)scores_[id]+=1-decay_;
        return true;
    }
    std::vector<uint32_t> Predict(size_t count){
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<uint32_t> ids;
        for(size_t i=0;i<scores_.size()&&i<=UINT32_MAX;++i)if(scores_[i]>0)ids.push_back(uint32_t(i));
        std::sort(ids.begin(),ids.end(),[&](uint32_t a,uint32_t b){return scores_[a]==scores_[b]?a<b:scores_[a]>scores_[b];});
        if(ids.size()>count)ids.resize(count);
        return ids;
    }
};
} }
