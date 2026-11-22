#pragma once
#include "ReapCalibrationState.hpp"
#include <algorithm>
#include <map>
#include <stdexcept>

namespace Deep2 { namespace ReapSaliency {
// Observer order in computeMoEFFN: shared output, route, routed outputs.
// Completed rows are committed only after every selected expert is observed.
class Accumulator {
    struct Pending { uint32_t id; float weight; bool seen=false; double score=0; };
    using Key=std::pair<uint32_t,uint32_t>;
    const std::vector<bool> expected_;
    const uint32_t experts_, top_, width_;
    std::vector<uint64_t> promptRoutes_;
    std::vector<Pending> pending_;
    std::map<Key,ReapState::Metric> metrics_;
    uint32_t layer_=0;
    uint64_t step_=0, observations_=0, promptStart_=0;
    enum class Phase { Idle, Shared, Routed } phase_=Phase::Idle;
    bool failed_=false, promptActive_=false;
    bool fail() noexcept { failed_=true; return false; }
    bool expected(uint32_t layer) const {return layer<expected_.size()&&expected_[layer];}
    static bool norm(const float* data,uint32_t n,double& result) {
        if(!data)return false;
        double sum=0;for(uint32_t i=0;i<n;++i){double x=data[i];if(!std::isfinite(x))return false;sum+=x*x;}
        result=std::sqrt(sum);return std::isfinite(result);
    }
public:
    Accumulator(std::vector<bool> expected,uint32_t experts,uint32_t top,uint32_t width)
        :expected_(std::move(expected)),experts_(experts),top_(top),width_(width),promptRoutes_(expected_.size()) {
        if(!experts_||!top_||top_>experts_||!width_||expected_.size()>UINT32_MAX||
           std::find(expected_.begin(),expected_.end(),true)==expected_.end())throw std::invalid_argument("invalid saliency topology");
        pending_.reserve(top_);
    }
    bool BeginPrompt(){if(failed_||promptActive_||phase_!=Phase::Idle)return fail();std::fill(promptRoutes_.begin(),promptRoutes_.end(),0);promptStart_=observations_;promptActive_=true;return true;}
    bool Route(uint32_t layer,uint64_t step,uint32_t width,uint32_t count,const uint32_t* ids,const float* weights,const float* input){
        if(failed_||!promptActive_||phase_!=Phase::Shared||layer!=layer_||step!=step_||width!=width_||count!=top_||!ids||!weights||!input)return fail();
        for(uint32_t i=0;i<width;++i)if(!std::isfinite(input[i]))return fail();
        pending_.clear();
        for(uint32_t i=0;i<count;++i){if(ids[i]>=experts_||!std::isfinite(weights[i])||weights[i]<0||std::any_of(pending_.begin(),pending_.end(),[&](const auto& p){return p.id==ids[i];}))return fail();pending_.push_back({ids[i],weights[i]});}
        phase_=Phase::Routed;return true;
    }
    bool Output(uint32_t layer,uint64_t step,uint32_t kind,uint32_t id,float weight,uint32_t width,const float* data){
        double magnitude=0;
        if(failed_||!promptActive_||!expected(layer)||width!=width_||!norm(data,width,magnitude))return fail();
        if(kind==0){if(phase_!=Phase::Idle||id!=UINT32_MAX||weight!=1.0f)return fail();layer_=layer;step_=step;phase_=Phase::Shared;return true;}
        if(kind!=1||phase_!=Phase::Routed||layer!=layer_||step!=step_)return fail();
        auto it=std::find_if(pending_.begin(),pending_.end(),[&](const auto& p){return p.id==id;});
        if(it==pending_.end()||it->seen||it->weight!=weight)return fail();
        it->score=double(weight)*magnitude;it->seen=true;
        if(std::any_of(pending_.begin(),pending_.end(),[](const auto& p){return !p.seen;}))return true;
        if(observations_==UINT64_MAX||promptRoutes_[layer]==UINT64_MAX)return fail();
        for(const auto& p:pending_){auto& m=metrics_[{layer,p.id}];if(m.count==UINT64_MAX||!std::isfinite(m.activation+p.score))return fail();m.layer=layer;m.expert=p.id;}
        for(const auto& p:pending_){auto& m=metrics_.at({layer,p.id});++m.count;m.activation+=p.score;}
        ++observations_;++promptRoutes_[layer];phase_=Phase::Idle;return true;
    }
    bool EndPrompt(uint64_t& routes){if(failed_||!promptActive_||phase_!=Phase::Idle)return fail();for(size_t i=0;i<expected_.size();++i)if(expected_[i]&&!promptRoutes_[i])return fail();routes=observations_-promptStart_;promptActive_=false;return routes!=0;}
    bool Snapshot(const std::vector<uint64_t>& completed,ReapState::State& state) const {
        if(failed_||promptActive_||phase_!=Phase::Idle)return false;
        ReapState::State s;s.completed=completed;s.observations=observations_;for(const auto& row:metrics_)s.metrics.push_back(row.second);state=std::move(s);return true;
    }
    bool Restore(const ReapState::Identity& identity,const ReapState::State& state){
        if(failed_||promptActive_||observations_||identity.layers!=expected_.size()||identity.experts!=experts_||identity.topK!=top_||!ReapState::valid(identity,state))return false;
        std::vector<uint64_t> counts(expected_.size());std::map<Key,ReapState::Metric> restored;
        for(const auto& m:state.metrics){if(!expected(m.layer)||m.weight!=0||m.count>UINT64_MAX-counts[m.layer])return false;counts[m.layer]+=m.count;restored.emplace(Key{m.layer,m.expert},m);}
        for(size_t i=0;i<counts.size();++i)if(expected_[i]&&(!counts[i]||counts[i]%top_))return false;
        for(const auto& m:state.metrics)if(m.count>counts[m.layer]/top_)return false;
        metrics_.swap(restored);observations_=state.observations;return true;
    }
    bool WriteScores(std::ostream& out) const {
        if(failed_||promptActive_||phase_!=Phase::Idle||!observations_)return false;
        std::vector<ReapState::Metric> sorted;for(const auto& row:metrics_)sorted.push_back(row.second);
        std::sort(sorted.begin(),sorted.end(),[](const auto& a,const auto& b){if(a.layer!=b.layer)return a.layer<b.layer;double x=a.activation/a.count,y=b.activation/b.count;return x==y?a.expert<b.expert:x>y;});
        out.imbue(std::locale::classic());out<<std::setprecision(17)<<"layer\texpert\troutes\tweighted_norm_sum\tmean_weighted_norm\n";
        for(const auto& m:sorted)out<<m.layer<<'\t'<<m.expert<<'\t'<<m.count<<'\t'<<m.activation<<'\t'<<m.activation/m.count<<'\n';
        return bool(out);
    }
};
} } // namespace Deep2::ReapSaliency
