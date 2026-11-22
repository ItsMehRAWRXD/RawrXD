#include "deep2/ReapCalibrationState.hpp"
#include "deep2/ReapRouteTracker.hpp"
#include "deep2/ReapShardIdentity.hpp"
#include <cstdio>
#include <sstream>
using namespace Deep2;
using namespace Deep2::ReapState;
int main(){
    int pass=0,fail=0;auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);ok?++pass:++fail;};
    std::vector<std::filesystem::path> paths;
    check(ShardPaths("models/kimi-00001-of-00013.gguf",paths)&&paths.size()==13&&paths.back()==std::filesystem::path("models/kimi-00013-of-00013.gguf"),"canonical complete shard set");
    check(!ShardPaths("models/kimi-00002-of-00013.gguf",paths),"reject nonfirst shard");
    check(!ShardPaths("models/kimi-00001-of-00000.gguf",paths),"reject zero shards");
    check(!ShardPaths("models/kimi-00001-of-99999.gguf",paths),"reject oversized shard set");
    check(!ShardPaths("models/kimi-00001-of-00A13.gguf",paths),"reject malformed shard count");
    check(ShardPaths("model.gguf",paths)&&paths.size()==1&&paths[0]==std::filesystem::path("model.gguf"),"single file");
    check(ShardPaths("a-00001-of-00002.GGUF",paths)&&paths.size()==2,"uppercase extension");
    ReapActivationAccumulator uninterrupted, first, resumed;
    auto prompt1=[](ReapActivationAccumulator& a){a.Observe(1,{}, {0,2},{0.75f,0.25f});a.Observe(1,{}, {2,3},{0.5f,0.5f});};
    auto prompt2=[](ReapActivationAccumulator& a){a.Observe(1,{}, {0,3},{0.8f,0.2f});a.Observe(2,{}, {1,7},{0.1f,0.9f});};
    prompt1(uninterrupted);prompt2(uninterrupted);prompt1(first);
    Identity id{"two-shard-identity","configuration",4,8,2,{"prompt one","prompt two"}};
    State state;state.observations=first.tokenCount();state.completed={2,0};
    for(const auto& entry:first.Snapshot())state.metrics.push_back({static_cast<uint32_t>(entry.first.first),static_cast<uint32_t>(entry.first.second),entry.second.routeCount,entry.second.activationSum,entry.second.weightSum});
    std::stringstream serialized;State read;
    check(Write(serialized,id,state)&&Read(serialized,id,read),"production accumulator snapshot resumes");
    decltype(resumed.Snapshot()) restored;
    for(const auto& m:read.metrics)restored.emplace(std::make_pair(size_t(m.layer),size_t(m.expert)),ReapExpertMetric{m.count,m.activation,m.weight});
    resumed.Restore(std::move(restored),read.observations);
    check(resumed.tokenCount()==first.tokenCount(),"restored route observations");
    prompt2(resumed);auto expected=uninterrupted.Snapshot(),actual=resumed.Snapshot();
    bool same=expected.size()==actual.size();
    for(const auto& entry:expected){auto it=actual.find(entry.first);same=same&&it!=actual.end()&&it->second.routeCount==entry.second.routeCount&&it->second.activationSum==entry.second.activationSum&&it->second.weightSum==entry.second.weightSum;}
    check(same&&resumed.tokenCount()==uninterrupted.tokenCount(),"resumed equals uninterrupted exact metrics");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
