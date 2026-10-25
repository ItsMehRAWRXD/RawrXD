#include "Deep2Engine.h"
#include "deep2/ReapRouteTracker.hpp"
#include "deep2/MlaCertAuthority.hpp"
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

static std::string jsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (unsigned char c : value) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                static constexpr char hex[] = "0123456789abcdef";
                out += "\\u00";
                out += hex[(c >> 4) & 0x0f];
                out += hex[c & 0x0f];
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    return out;
}

struct ReplayResponse {
    std::string prompt;
    std::string response;
};

template <typename MetricsMap>
static void writeMetrics(std::ostream& out, const MetricsMap& metrics) {
    out << '[';
    bool first = true;
    for (const auto& kv : metrics) {
        if (!first) out << ',';
        first = false;
        out << "{\"layer\":" << kv.first.first
            << ",\"expert\":" << kv.first.second
            << ",\"route_count\":" << kv.second.routeCount
            << ",\"activation_sum\":" << kv.second.activationSum
            << ",\"weight_sum\":" << kv.second.weightSum << '}';
    }
    out << ']';
}

static void writeResponses(std::ostream& out, const std::vector<ReplayResponse>& responses) {
    out << '[';
    bool first = true;
    for (const auto& item : responses) {
        if (!first) out << ',';
        first = false;
        out << "{\"prompt\":\"" << jsonEscape(item.prompt)
            << "\",\"response\":\"" << jsonEscape(item.response)
            << "\",\"response_bytes\":" << item.response.size() << '}';
    }
    out << ']';
}

int main(int argc,char**argv){
    if(argc<4||argc>6){std::cerr<<"usage: rawr-reap-replay <model.gguf> <corpus.jsonl> <receipt.json> [window-limit] [--require-mla]\n";return 2;}
    // The window limit is present whenever an optional argument is supplied;
    // the certification flag is a separate argument and must not make the
    // replay silently fall back to the default 256-window run.
    const size_t limit = argc>=5 ? std::strtoull(argv[4],nullptr,10) : 256;
    if(limit==0 || limit>256){std::cerr<<"INVALID_WINDOW_LIMIT\n";return 2;}
    const bool requireMla = argc==6 && std::string(argv[5])=="--require-mla";
    if(argc==6 && !requireMla){std::cerr<<"INVALID_CERTIFICATION_MODE\n";return 2;}
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
    std::string line; size_t n=0; size_t generated=0; std::vector<ReplayResponse> responses;
    while(n<limit && std::getline(in,line)) {
        auto text=jsonText(line);
        if(text.empty()) continue;
        auto result=engine.generateText(text,1);
        responses.push_back({text, result});
        if(!result.empty()) ++generated;
        ++n;
        std::cout << "REPLAY_RESPONSE[" << (n - 1) << "]="
                  << result << "\n";
        if((n%8)==0) std::cerr<<"REPLAY_PROGRESS="<<n<<"/"<<limit<<"\n";
        if(std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now()-started).count()>=30){std::cerr<<"REPLAY_TIMEOUT\n";break;}
    }
    Deep2::ReapRouteTracker::Instance().Clear(); auto m=acc.Snapshot();
    const bool mlaSeal = Deep2::MlaCertAuthority::ProductSealPass();
    // Dense models have no MoE route observations.  That is valid calibration
    // evidence, not an incomplete run; the receipt records the distinction.
    const bool complete = n==limit && generated==n;
    const bool certificationBlocked = requireMla && (m.empty() || !mlaSeal);
    const auto elapsedMs=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
    std::ofstream out(argv[3],std::ios::binary); if(!out)return 4;
    out<<"{\"schema\":\"RAWRXD_REAP_CALIBRATION_001\",\"model\":\""<<jsonEscape(argv[1])
       <<"\",\"corpus\":\""<<jsonEscape(argv[2])
       <<"\",\"windows\":"<<n<<",\"generated\":"<<generated
       <<",\"elapsed_ms\":"<<elapsedMs
       <<",\"complete\":"<<(complete?"true":"false")
       <<",\"route_metrics_available\":"<<(m.empty()?"false":"true")
       <<",\"mla_product_seal\":"<<(mlaSeal?"true":"false")
       <<",\"certification\":\""<<(complete && mlaSeal && !m.empty()?"CERTIFIED_MLA_MOE":"CALIBRATED_UNSEALED")
       <<"\",\"responses\":";
    writeResponses(out, responses);
    out << ",\"metrics\":";
    writeMetrics(out, m);
    out << "}\n";
    std::cout<<"REPLAY_WINDOWS="<<n<<" GENERATED="<<generated<<" METRICS="<<m.size()<<" COMPLETE="<<(complete?1:0)<<"\n";
    if(!complete){std::cerr<<"REPLAY_INCOMPLETE windows="<<n<<" generated="<<generated<<" metrics="<<m.size()<<"\n";return 4;}
    if(certificationBlocked){std::cerr<<"MLA_CERTIFICATION_BLOCKED routes="<<m.size()<<" product_seal="<<(mlaSeal?1:0)<<"\n";return 5;}
    return 0;
}
