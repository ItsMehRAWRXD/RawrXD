#include "Deep2Engine.h"
#include "deep2/ReapRouteTracker.hpp"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <cstdlib>
#include <chrono>
#ifdef _WIN32
#include <cstdio>
#include <io.h>
#endif

static std::string jsonText(const std::string& line) {
    const std::string key="\"text\":\""; auto p=line.find(key); if(p==std::string::npos) return {};
    p+=key.size(); std::string out; bool esc=false;
    for(;p<line.size();++p){ char c=line[p]; if(esc){ if(c=='n')out+='\n'; else if(c=='r')out+='\r'; else if(c=='t')out+='\t'; else out+=c; esc=false; continue;} if(c=='\\'){esc=true;continue;} if(c=='\"')break; out+=c; } return out;
}
int main(int argc,char**argv){
    if(argc<4||argc>5){std::cerr<<"usage: rawr-reap-replay <model.gguf> <corpus.jsonl> <receipt.json> [window-limit]\n";return 2;}
    const size_t limit = argc==5 ? std::strtoull(argv[4],nullptr,10) : 256;
    if(limit==0 || limit>256){std::cerr<<"INVALID_WINDOW_LIMIT\n";return 2;}
    if(const char* q=std::getenv("RAWR_REAP_QUIET"); q && q[0]=='1') {
#ifdef _WIN32
        FILE* nul=std::fopen("NUL","w");
        if(nul){ std::fflush(stdout); std::fflush(stderr); _dup2(_fileno(nul),_fileno(stdout)); _dup2(_fileno(nul),_fileno(stderr)); }
#endif
    }
    const auto started=std::chrono::steady_clock::now();
    Deep2::ReapActivationAccumulator acc; acc.Reset();
    Deep2::ReapRouteTracker::Instance().Install([&](size_t l,const auto& p,const auto& ids,const auto& w){acc.Observe(l,p,ids,w);});
    Deep2::Deep2Engine engine;
    if(!engine.loadModel(argv[1])){std::cerr<<"MODEL_LOAD_FAILED\n"; Deep2::ReapRouteTracker::Instance().Clear(); return 4;}
    std::ifstream in(argv[2]); if(!in){std::cerr<<"CORPUS_OPEN_FAILED\n"; return 4;}
    std::string line; size_t n=0; while(n<limit && std::getline(in,line)){ auto text=jsonText(line); if(text.empty()) continue; auto result=engine.generateText(text,1); (void)result; ++n; if((n%8)==0) std::cerr<<"REPLAY_PROGRESS="<<n<<"/"<<limit<<"\n"; if(std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now()-started).count()>=30){std::cerr<<"REPLAY_TIMEOUT\n";break;} }
    Deep2::ReapRouteTracker::Instance().Clear(); auto m=acc.Snapshot();
    if(n!=limit || m.empty()){std::cerr<<"REPLAY_INCOMPLETE windows="<<n<<" metrics="<<m.size()<<"\n";return 4;}
    std::ofstream out(argv[3],std::ios::binary); if(!out)return 4;
    out<<"{\"model\":\""<<argv[1]<<"\",\"corpus\":\""<<argv[2]<<"\",\"windows\":"<<n<<",\"metrics\":["; bool first=true;
    for(const auto& kv:m){if(!first)out<<',';first=false;out<<"{\"layer\":"<<kv.first.first<<",\"expert\":"<<kv.first.second<<",\"route_count\":"<<kv.second.routeCount<<",\"activation_sum\":"<<kv.second.activationSum<<",\"weight_sum\":"<<kv.second.weightSum<<"}";} out<<"]}\n"; std::cout<<"REPLAY_WINDOWS="<<n<<" METRICS="<<m.size()<<"\n"; return 0;
}
