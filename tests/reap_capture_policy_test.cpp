#include "deep2/ReapCapturePolicy.hpp"
#include <cstdio>
using namespace Deep2::ReapCapture;
int main() {
    int pass=0, fail=0;
    auto check=[&](bool ok,const char* label){std::printf("%s %s\n",ok?"PASS":"FAIL",label);ok?++pass:++fail;};
    check(CaptureRouting(false,false,3,0,3,0),"legacy first route");
    check(!CaptureRouting(true,false,3,0,3,0),"legacy once only");
    check(!CaptureRouting(false,false,AllLayers,AllSteps,3,0),"legacy layer sentinel disabled");
    check(CaptureRouting(true,true,AllLayers,AllSteps,3,0),"stream subsequent route");
    check(CaptureRouting(true,true,AllLayers,AllSteps,9,123),"stream all layers and steps");
    check(!CaptureRouting(false,true,3,AllSteps,9,0),"specific layer preserved");
    check(!CaptureRouting(false,true,AllLayers,0,3,1),"specific step preserved");
    check(Matches(AllLayers,AllSteps,59,99,true),"expert output wildcard");
    check(!Matches(AllLayers,AllSteps,59,99,false),"legacy output wildcard disabled");
    check(CompleteCounts(2,2,16,18,8),"Kimi top-eight coverage");
    check(CompleteCounts(3,3,18,21,6),"top-six coverage");
    check(!CompleteCounts(2,2,12,14,8),"truncated top-eight rejected");
    check(!CompleteCounts(2,1,16,17,8),"missing shared record");
    check(!CompleteCounts(2,2,17,19,8),"extra routed record");
    check(!CompleteCounts(2,2,16,17,8),"bad total");
    check(!CompleteCounts(0,0,0,0,8),"empty rejected");
    check(!CompleteCounts(2,2,0,2,0),"zero top-k rejected");
    check(!CompleteCounts(UINT64_MAX,UINT64_MAX,0,0,8),"multiplication overflow rejected");
    check(!CompleteCounts(UINT64_MAX,UINT64_MAX,UINT64_MAX,0,1),"addition overflow rejected");
    std::vector<bool> expected{false,true,false,true};
    std::vector<LayerCounts> layers{{},{2,2,16,18},{},{3,3,24,27}};
    check(CompleteCoverage(expected,layers,8),"all routed layers present");
    auto bad=layers;bad[3]={};
    check(!CompleteCoverage(expected,bad,8),"missing routed layer");
    bad=layers;bad[0]={1,1,8,9};
    check(!CompleteCoverage(expected,bad,8),"unexpected dense layer");
    bad=layers;bad[3].routed=23;
    check(!CompleteCoverage(expected,bad,8),"per-layer incomplete output");
    check(!CompleteCoverage({false},{{}},8),"no expected layers rejected");
    check(!CompleteCoverage(expected,{{}},8),"mismatched topology rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
