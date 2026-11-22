#include "reap/ReapVisitSchedule.hpp"
#include <cstdio>
#include <algorithm>
#include <vector>
using namespace reap;
int main() {
    int pass=0, fail=0;
    auto check=[&](bool ok,const char* label){std::printf("%s %s\n",ok?"PASS":"FAIL",label);ok?++pass:++fail;};
    auto reject=[&](const char* label,auto f){try{f();check(false,label);}catch(const std::exception&){check(true,label);}};
    auto loop=NormalizeLoop("inkling2_loop",24,3,6,18);
    auto visits=BuildLayerVisits(loop);
    check(loop.end==19,"inclusive endpoint normalized");
    check(visits.size()==50,"24 layers plus 26 recurrent visits");
    std::vector<uint32_t> expected;
    for(uint32_t b=0;b<6;++b) expected.push_back(b);
    for(int p=0;p<3;++p) for(uint32_t b=6;b<=18;++b) expected.push_back(b);
    for(uint32_t b=19;b<24;++b) expected.push_back(b);
    bool order=visits.size()==expected.size(), ordinal=true;
    std::vector<unsigned> counts(24);
    for(size_t i=0;i<visits.size();++i){order=order && i<expected.size() && visits[i].physicalLayer==expected[i];ordinal=ordinal && visits[i].layerOrdinal==i; ++counts.at(visits[i].physicalLayer);}
    check(order,"prefix loop suffix execution order");
    check(ordinal,"contiguous ordinal");
    bool mult=true;
    for(size_t i=0;i<counts.size();++i) mult=mult && counts[i]==VisitMultiplicity(loop,i) && counts[i]==(i>=6 && i<=18?3u:1u);
    check(mult,"inventory multiplicity equals actual schedule");
    check(counts[5]==1 && counts[6]==3 && counts[18]==3 && counts[19]==1,"boundary layers");
    auto exclusive=BuildLayerVisits(NormalizeLoop("inkling",8,2,2,5));
    check(exclusive.size()==11 && exclusive[2].physicalLayer==2 && exclusive[5].physicalLayer==2 && exclusive[8].physicalLayer==5,"exclusive partial loop");
    check(BuildLayerVisits(NormalizeLoop("inkling",24,2,0,24)).size()==48,"legacy full loop");
    check(BuildLayerVisits(NormalizeLoop("llama",32,0,0,0)).size()==32,"dense model");
    check(BuildLayerVisits(NormalizeLoop("inkling",8,1,2,5)).size()==8,"single pass includes all layers");
    auto one=NormalizeLoop("inkling2_loop",4,2,0,0);
    check(one.visits==5 && VisitMultiplicity(one,0)==2 && VisitMultiplicity(one,1)==1,"inclusive single layer zero");
    check(BuildLayerVisits(NormalizeLoop("inkling",4,2,0,0)).size()==8,"exclusive default end");
    reject("out of range inclusive",[]{NormalizeLoop("inkling2_loop",8,3,2,8);});
    reject("reversed range",[]{NormalizeLoop("inkling",8,3,6,4);});
    reject("empty range",[]{NormalizeLoop("inkling",8,3,2,2);});
    reject("visit overflow",[]{NormalizeLoop("inkling",2,UINT32_MAX,0,2);});
    reject("block overflow",[]{NormalizeLoop("llama",uint64_t{UINT32_MAX}+1,1,0,0);});
    reject("unmapped layer",[&]{VisitMultiplicity(loop,24);});
    std::printf("%d passed, %d failed\n",pass,fail);
    return fail?1:0;
}
