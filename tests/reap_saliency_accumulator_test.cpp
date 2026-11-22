#include "deep2/ReapSaliencyAccumulator.hpp"
#include <cstdio>
#include <sstream>
using namespace Deep2;
using ReapSaliency::Accumulator;
int main(){
    int pass=0,fail=0;auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);ok?++pass:++fail;};
    const uint32_t ids[]={0,1};const float weights[]={0.75f,0.25f},shared[]={0,0},a[]={1,0},b[]={0,20};
    auto route=[&](Accumulator& x,uint32_t layer=1,uint64_t step=0){return x.Output(layer,step,0,UINT32_MAX,1,2,shared)&&x.Route(layer,step,2,2,ids,weights,shared)&&x.Output(layer,step,1,1,.25f,2,b)&&x.Output(layer,step,1,0,.75f,2,a);};
    auto prompt=[&](Accumulator& x){uint64_t n=0;return x.BeginPrompt()&&route(x)&&route(x,3)&&x.EndPrompt(n)&&n==2;};
    Accumulator x({false,true,false,true},8,2,2);check(prompt(x),"actual observer order and reordered outputs");
    std::ostringstream scores;check(x.WriteScores(scores)&&scores.str()=="layer\texpert\troutes\tweighted_norm_sum\tmean_weighted_norm\n1\t1\t1\t5\t5\n1\t0\t1\t0.75\t0.75\n3\t1\t1\t5\t5\n3\t0\t1\t0.75\t0.75\n","activation aware scorer compatible TSV");
    ReapState::Identity identity{"model","config",4,8,2,{"first","second"},"RAWRXD_REAP_SALIENCY_STATE_001"};
    ReapState::State state,read;std::stringstream buffer;
    check(x.Snapshot({2,0},state)&&ReapState::Write(buffer,identity,state)&&ReapState::Read(buffer,identity,read),"persistent state");
    auto wrong=identity;wrong.schema="RAWRXD_REAP_ROUTING_STATE_002";std::stringstream mismatched(buffer.str());check(!ReapState::Read(mismatched,wrong,read),"legacy schema rejected");
    Accumulator resumed({false,true,false,true},8,2,2);check(resumed.Restore(identity,read),"restore actual saliency");
    check(prompt(x)&&prompt(resumed),"continue both accumulators");std::ostringstream s1,s2;check(x.WriteScores(s1)&&resumed.WriteScores(s2)&&s1.str()==s2.str(),"exact uninterrupted vs resumed scores");
    auto reject=[&](auto f){Accumulator t({false,true,false,true},8,2,2);return t.BeginPrompt()&&!f(t)&&!t.WriteScores(scores);};
    check(reject([&](auto& t){return t.Route(1,0,2,2,ids,weights,shared);}),"route before shared rejected");
    check(reject([&](auto& t){return t.Output(0,0,0,UINT32_MAX,1,2,shared);}),"unexpected layer rejected");
    check(reject([&](auto& t){return t.Output(1,0,0,UINT32_MAX,1,2,shared)&&t.Route(1,1,2,2,ids,weights,shared);}),"mismatched step rejected");
    check(reject([&](auto& t){uint32_t duplicate[]={0,0};return t.Output(1,0,0,UINT32_MAX,1,2,shared)&&t.Route(1,0,2,2,duplicate,weights,shared);}),"duplicate route rejected");
    check(reject([&](auto& t){return t.Output(1,0,0,UINT32_MAX,1,2,shared)&&t.Route(1,0,2,2,ids,weights,shared)&&t.Output(1,0,1,1,.5f,2,b);}),"weight mismatch rejected");
    check(reject([&](auto& t){uint64_t n=0;return route(t)&&t.EndPrompt(n);}),"missing expected layer rejected");
    check(reject([&](auto& t){uint64_t n=0;return t.Output(1,0,0,UINT32_MAX,1,2,shared)&&t.Route(1,0,2,2,ids,weights,shared)&&t.Output(1,0,1,1,.25f,2,b)&&t.EndPrompt(n);}),"incomplete output rejected");
    check(reject([&](auto& t){float bad[]={0,std::numeric_limits<float>::infinity()};return t.Output(1,0,0,UINT32_MAX,1,2,bad);}),"nonfinite output rejected");
    check(reject([&](auto& t){return t.Output(1,0,0,UINT32_MAX,1,2,shared)&&t.Route(1,0,2,2,ids,weights,shared)&&t.Output(1,0,1,1,.25f,2,b)&&t.Output(1,0,1,1,.25f,2,b);}),"duplicate output rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
