#include "deep2/ReapExportBudget.hpp"
#include <cstdio>
using namespace Deep2::ReapExport;
int main(){
    int pass=0,fail=0;auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);ok?++pass:++fail;};
    Router r{384,8,8,4};
    check(r.Valid(),"grouped source");check(!r.Allows(8)&&r.Allows(16),"group capacity minimum");
    check(!r.Allows(17)&&r.Allows(32),"uniform groups");
    GroupFields f;check(f.Observe(f.groups,8)&&f.Observe(f.used,4)&&f.Observe(f.width,48),"metadata fields");
    Router resolved;check(f.Resolve(384,8,resolved)&&resolved.groups==8&&resolved.used==4,"resolve source geometry");
    check(!f.Observe(f.groups,4),"conflicting shard metadata");
    f.width=24;check(!f.Resolve(384,8,resolved),"inconsistent group width");
    check(!GroupFields{8,0,0}.Resolve(384,8,resolved),"missing grouped top-k");
    check(GroupFields{}.Resolve(8,2,resolved)&&resolved.groups==1,"ungrouped default");
    check(GroupFields{0,2,4}.Resolve(8,2,resolved)&&resolved.groups==2,"derive groups from width");
    Router small{8,2,2,1};
    check(small.Preserves({0,3,4,7}),"balanced ordered group map");
    check(!small.Preserves({0,1,2,4}),"group imbalance rejected");
    check(!small.Preserves({4,7,0,3}),"group reorder rejected");
    check(!small.Preserves({0,0,4,7}),"duplicate rejected");
    check(!small.Preserves({0,3,4,8}),"out of range rejected");
    Shard first{65,32,{{35,false},{800,true},{32,true}}};
    Shard dense{31,32,{{17,false}}};
    std::vector<Shard> shards{first,dense}; U n=0;
    check(Measure(first,small,4,n)&&n==592,"aligned serialized size");
    check(MeasureAll(shards,small,4,n)&&n==641,"dense shard included");
    check(MeasureAll(shards,small,6,n)&&n==841,"six experts exact size");
    check(MaxRetained(shards,small,840,n)&&n==4,"budget selects largest feasible bank");
    check(MaxRetained(shards,small,841,n)&&n==6,"exact boundary accepted");
    check(MaxRetained(shards,small,640,n)&&n==0,"infeasible budget");
    check(MaxRetained(shards,small,UINT64_MAX,n)&&n==8,"all experts fit");
    check(!Measure(Shard{65,3,{{8,true}}},small,4,n),"invalid alignment");
    check(!Measure(Shard{65,32,{{7,true}}},small,4,n),"fractional expert bytes");
    check(!Measure(Shard{UINT64_MAX,32,{{8,true}}},small,4,n),"header alignment overflow");
    check(!Measure(Shard{32,32,{{UINT64_MAX,false}}},small,4,n),"payload overflow");
    check(!MeasureAll({},small,4,n),"empty source rejected");
    check(!Measure(Shard{32,32,{{0,false}}},small,4,n),"empty payload rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
