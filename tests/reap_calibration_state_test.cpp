#include "deep2/ReapCalibrationState.hpp"
#include <cstdio>
#include <sstream>
using namespace Deep2::ReapState;
int main(int argc,char** argv){
    if(argc!=2)return 2;
    int pass=0,fail=0;auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);ok?++pass:++fail;};
    Identity id{"source hash","config",4,8,2,{"first \"quoted\"\nline","second","third"}};
    State a{3,{3,0,0},{{1,0,3,1.25,1.25},{1,2,3,1.75,1.75}}};
    std::stringstream buf;check(Write(buf,id,a),"serialize real counters");const auto serialized=buf.str();
    State b;check(Read(buf,id,b)&&b.completed==a.completed&&b.observations==3&&b.metrics.size()==2&&b.metrics[1].weight==1.75,"roundtrip ordered prompts and metrics");
    auto reject=[&](Identity want,std::string text){std::stringstream input(text);State s=a;return !Read(input,want,s)&&s.observations==3&&s.metrics[0].weight==1.25;};
    auto wrong=id;std::swap(wrong.prompts[0],wrong.prompts[1]);check(reject(wrong,serialized),"prompt order rejected");
    wrong=id;wrong.model="other";check(reject(wrong,serialized),"model mismatch");
    wrong=id;wrong.config="other";check(reject(wrong,serialized),"config mismatch");
    wrong=id;wrong.topK=3;check(reject(wrong,serialized),"topology mismatch");
    check(reject(id,serialized.substr(0,serialized.size()/2)),"truncated state rejected");
    check(reject(id,serialized+"garbage"),"trailing data rejected");
    auto bad=a;bad.completed={1,0,2};check(!valid(id,bad),"noncontiguous progress");
    bad=a;bad.observations=4;check(!valid(id,bad),"observation total mismatch");
    bad=a;bad.metrics[1].count=2;check(!valid(id,bad),"route total mismatch");
    bad=a;bad.metrics[1].expert=0;check(!valid(id,bad),"duplicate expert");
    bad=a;bad.metrics[1].layer=4;check(!valid(id,bad),"layer range");
    bad=a;bad.metrics[1].expert=8;check(!valid(id,bad),"expert range");
    bad=a;bad.metrics[1].activation=std::numeric_limits<double>::infinity();check(!valid(id,bad),"nonfinite metric");
    bad=a;bad.metrics[1].weight=2;check(!valid(id,bad),"weight exceeds magnitude");
    bad=a;bad.completed={UINT64_MAX,1,0};check(!valid(id,bad),"progress overflow");
    const auto dir=std::filesystem::path(argv[1]);std::filesystem::create_directories(dir);const auto path=dir/"resume.state";
    check(Save(path,id,a)&&Load(path,id,b),"disk checkpoint roundtrip");
    State next{5,{3,2,0},{{1,0,5,2.5,2.5},{1,2,5,2.5,2.5}}};
    check(Save(path,id,next)&&Load(path,id,b)&&b.observations==5&&b.completed[1]==2,"atomic checkpoint replacement");
    check(!Save(path,id,bad)&&Load(path,id,b)&&b.observations==5,"invalid update preserves prior checkpoint");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
