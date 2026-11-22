// Native offline REAP saliency from paired Deep2 P2-C observer captures.
// Outputs measured rankings only, never a rewrite authorization.
#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
class Reader {
    std::ifstream in_;
public:
    explicit Reader(const char* path) : in_(path,std::ios::binary) {
        if(!in_) throw std::runtime_error("cannot open capture");
    }
    bool More() {
        if(in_.peek()!=std::char_traits<char>::eof()) return true;
        if(in_.bad() || !in_.eof()) throw std::runtime_error("capture read failure");
        return false;
    }
    template<class T> T Read() {
        T v{};
        if(!in_.read(reinterpret_cast<char*>(&v),sizeof(v))) throw std::runtime_error("truncated capture");
        return v;
    }
    float Float() {
        const float v=Read<float>();
        if(!std::isfinite(v)) throw std::runtime_error("nonfinite capture");
        return v;
    }
};
uint32_t Positive(const char* s) {
    uint32_t n=0; const std::string str(s);
    const auto r=std::from_chars(str.data(),str.data()+str.size(),n);
    if(r.ec!=std::errc{} || r.ptr!=str.data()+str.size() || !n) throw std::runtime_error("invalid count");
    return n;
}
struct Metric { uint64_t count=0; double sum=0; };
struct Observation { uint32_t layer; uint64_t step; uint32_t kind,id; float weight; uint32_t width; };
Observation Header(Reader& r) {
    Observation o{};o.layer=r.Read<uint32_t>();o.step=r.Read<uint64_t>();o.kind=r.Read<uint32_t>();
    o.id=r.Read<uint32_t>();o.weight=r.Float();o.width=r.Read<uint32_t>();return o;
}
double Norm(Reader& r,uint32_t n) {
    double sum=0;for(uint32_t i=0;i<n;++i) {const double v=r.Float();sum+=v*v;}
    return std::sqrt(sum);
}
}
int main(int argc,char** argv) {
    try {
        static_assert(sizeof(float)==4 && std::numeric_limits<float>::is_iec559,"IEEE binary32 required");
        if(argc!=6) throw std::runtime_error("usage: reap_activation_score ROUTES.bin OUTPUTS.bin EXPERT_COUNT TOP_K EXPECTED_ROUTE_RECORDS");
        const auto experts=Positive(argv[3]),topK=Positive(argv[4]),expected=Positive(argv[5]);
        if(topK>experts || experts>1000000) throw std::runtime_error("invalid expert topology");
        Reader routes(argv[1]), outputs(argv[2]);
        std::map<std::pair<uint32_t,uint32_t>,Metric> scores;
        uint64_t records=0;
        while(routes.More()) {
            if(++records>expected) throw std::runtime_error("extra route records");
            const auto layer=routes.Read<uint32_t>();const auto step=routes.Read<uint64_t>();
            const auto width=routes.Read<uint32_t>(), count=routes.Read<uint32_t>();
            if(!width || width>1000000 || count!=topK) throw std::runtime_error("route shape mismatch");
            std::vector<uint32_t> ids(count);for(auto& id:ids) {id=routes.Read<uint32_t>();if(id>=experts)throw std::runtime_error("invalid expert id");}
            std::map<uint32_t,float> weights;
            for(auto id:ids) {const auto w=routes.Float();if(w<0 || !weights.emplace(id,w).second)throw std::runtime_error("invalid route weight or duplicate id");}
            for(uint32_t i=0;i<width;++i) (void)routes.Float();
            auto shared=Header(outputs);
            if(shared.layer!=layer || shared.step!=step || shared.kind!=0 || shared.id!=UINT32_MAX || shared.weight!=1.0f || shared.width!=width) throw std::runtime_error("shared record mismatch");
            (void)Norm(outputs,width);
            for(uint32_t i=0;i<count;++i) {
                auto obs=Header(outputs);auto it=weights.find(obs.id);
                if(obs.layer!=layer || obs.step!=step || obs.kind!=1 || obs.width!=width || it==weights.end() || it->second!=obs.weight) throw std::runtime_error("expert output does not match applied route");
                const double contribution=double(obs.weight)*Norm(outputs,width);
                auto& m=scores[{layer,obs.id}];m.sum+=contribution;++m.count;weights.erase(it);
                if(!std::isfinite(m.sum)) throw std::runtime_error("score overflow");
            }
            if(!weights.empty()) throw std::runtime_error("missing expert outputs");
        }
        if(records!=expected || outputs.More()) throw std::runtime_error("incomplete or extra capture records");
        using Row=std::pair<std::pair<uint32_t,uint32_t>,Metric>;
        std::vector<Row> sorted(scores.begin(),scores.end());
        std::sort(sorted.begin(),sorted.end(),[](const Row& a,const Row& b){
            if(a.first.first!=b.first.first)return a.first.first<b.first.first;
            const auto x=a.second.sum/a.second.count,y=b.second.sum/b.second.count;
            return x==y?a.first.second<b.first.second:x>y;
        });
        std::cout<<"layer\texpert\troutes\tweighted_norm_sum\tmean_weighted_norm\n"<<std::setprecision(17);
        for(const auto& row:sorted)std::cout<<row.first.first<<'\t'<<row.first.second<<'\t'<<row.second.count<<'\t'<<row.second.sum<<'\t'<<row.second.sum/row.second.count<<'\n';
        std::cerr<<"ROUTE_RECORDS="<<records<<" MEASURED_EXPERTS="<<scores.size()<<"\nREWRITE_AUTHORIZED=0\n";
        return std::cout.good()?0:2;
    } catch(const std::exception& e) {std::cerr<<"INVALID_CAPTURE: "<<e.what()<<'\n';return 2;}
}
