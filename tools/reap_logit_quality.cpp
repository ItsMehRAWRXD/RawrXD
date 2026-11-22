// Standalone CPU-only evaluator of independent, teacher-forced F32 logit captures.
// Manifest columns (tab-separated, no header): sequence, position, input_id,
// next_id, logit_file (relative to manifest). Every sequence begins at position 0.
// The capture producers must independently attest model/tokenizer/runtime provenance.
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
namespace fs = std::filesystem;
struct Row { std::string seq; size_t pos, input, next; fs::path path; };
size_t number(const std::string& s) {
    if(s.empty() || s.find_first_not_of("0123456789") != std::string::npos) throw std::runtime_error("bad integer: " + s);
    size_t end=0; auto v=std::stoull(s,&end); if(end!=s.size() || v>std::numeric_limits<size_t>::max()) throw std::runtime_error("integer overflow"); return static_cast<size_t>(v);
}
double real(const std::string& s) { size_t end=0; double v=std::stod(s,&end); if(end!=s.size() || !std::isfinite(v)) throw std::runtime_error("bad threshold"); return v; }
std::vector<Row> manifest(const fs::path& p, size_t count, size_t vocab) {
    std::ifstream f(p); if(!f) throw std::runtime_error("manifest unavailable: "+p.string());
    std::vector<Row> out; std::set<std::string> sequences; std::set<fs::path> files; std::string line;
    while(std::getline(f,line)) {
        if(!line.empty() && line.back()=='\r') line.pop_back();
        std::vector<std::string> fields; size_t start=0;
        for(;;) { auto i=line.find('\t',start); fields.push_back(line.substr(start,i==std::string::npos?i:i-start)); if(i==std::string::npos) break; start=i+1; }
        if(fields.size()!=5 || fields[0].empty() || fields[4].empty()) throw std::runtime_error("invalid manifest row");
        Row r{fields[0],number(fields[1]),number(fields[2]),number(fields[3]),fs::canonical(p.parent_path()/fields[4])};
        if(r.input>=vocab || r.next>=vocab) throw std::runtime_error("token outside vocabulary");
        if(out.empty() || out.back().seq!=r.seq) { if(r.pos!=0 || !sequences.insert(r.seq).second) throw std::runtime_error("invalid sequence boundary"); }
        else if(r.pos!=out.back().pos+1 || r.input!=out.back().next) throw std::runtime_error("broken teacher-forced sequence");
        if(!files.insert(r.path).second) throw std::runtime_error("duplicate capture file");
        out.push_back(std::move(r)); if(out.size()>count) throw std::runtime_error("too many positions");
    }
    if(f.bad() || out.size()!=count) throw std::runtime_error("incomplete manifest");
    return out;
}
std::vector<float> logits(const fs::path& p,size_t n) {
    static_assert(sizeof(float)==4 && std::numeric_limits<float>::is_iec559,"IEEE F32 required");
    std::ifstream f(p,std::ios::binary|std::ios::ate); const auto bytes=n*4;
    if(!f || f.tellg()!=static_cast<std::streamoff>(bytes)) throw std::runtime_error("invalid logit size: "+p.string());
    std::vector<float> a(n); f.seekg(0); if(!f.read(reinterpret_cast<char*>(a.data()),static_cast<std::streamsize>(bytes))) throw std::runtime_error("logit read failure");
    for(float x:a) if(!std::isfinite(x)) throw std::runtime_error("non-finite logit: "+p.string());
    return a;
}
int main(int argc,char** argv) {
    try {
        if(argc!=10) throw std::runtime_error("usage: reap_logit_quality REF.tsv CAND.tsv VOCAB POSITIONS MIN_TOP1 MIN_COS MAX_ABS MAX_MEAN_KL MAX_PPL_RATIO");
        const size_t n=number(argv[3]), count=number(argv[4]);
        const double minTop=real(argv[5]), minCos=real(argv[6]), absLimit=real(argv[7]), klLimit=real(argv[8]), pplLimit=real(argv[9]);
        if(n<2 || n>10000000 || !count || minTop<0 || minTop>1 || minCos< -1 || minCos>1 || absLimit<0 || klLimit<0 || pplLimit<=0) throw std::runtime_error("invalid size or threshold");
        auto ref=manifest(argv[1],count,n), cand=manifest(argv[2],count,n);
        std::set<fs::path> refFiles; for(auto& r:ref) refFiles.insert(r.path);
        size_t matches=0; double worstAbs=0, worstCos=1, sumKL=0, nllR=0,nllC=0;
        for(size_t i=0;i<count;++i) {
            const auto& r=ref[i]; const auto& c=cand[i];
            if(r.seq!=c.seq || r.pos!=c.pos || r.input!=c.input || r.next!=c.next) throw std::runtime_error("mismatched token manifest");
            if(refFiles.count(c.path)) throw std::runtime_error("candidate reuses reference capture path");
            auto a=logits(r.path,n), b=logits(c.path,n);
            auto ia=std::max_element(a.begin(),a.end()), ib=std::max_element(b.begin(),b.end());
            matches+=(ia-a.begin()==ib-b.begin()); double ma=*ia,mb=*ib, za=0,zb=0,aa=0,bb=0,ab=0;
            for(size_t j=0;j<n;++j) { double x=a[j],y=b[j]; worstAbs=std::max(worstAbs,std::abs(x-y)); aa+=x*x; bb+=y*y; ab+=x*y; za+=std::exp(x-ma); zb+=std::exp(y-mb); }
            double cosine=(aa==0 || bb==0)?(aa==bb?1:0):std::clamp(ab/(std::sqrt(aa)*std::sqrt(bb)),-1.0,1.0);
            worstCos=std::min(worstCos,cosine); const double la=std::log(za),lb=std::log(zb); double kl=0;
            for(size_t j=0;j<n;++j) { double lp=double(a[j])-ma-la, lq=double(b[j])-mb-lb; kl+=std::exp(lp)*(lp-lq); }
            sumKL+=std::max(0.0,kl); nllR+=ma+la-double(a[r.next]); nllC+=mb+lb-double(b[r.next]);
        }
        double top=double(matches)/count, meanKL=sumKL/count, ratio=std::exp((nllC-nllR)/count);
        bool pass=top>=minTop && worstCos>=minCos && worstAbs<=absLimit && meanKL<=klLimit && std::isfinite(ratio) && ratio<=pplLimit;
        std::cout<<std::setprecision(12)<<"positions="<<count<<" vocab="<<n<<" top1="<<top<<" min_cos="<<worstCos<<" max_abs="<<worstAbs<<" mean_kl="<<meanKL<<" ref_nll="<<nllR/count<<" cand_nll="<<nllC/count<<" ppl_ratio="<<ratio<<"\nCAPTURE_METRICS="<<(pass?"PASS":"FAIL")<<"\nPROVENANCE_AND_SEMANTIC_QUALITY=NOT_CERTIFIED_BY_THIS_TOOL\n";
        return pass?0:1;
    } catch(const std::exception& e) { std::cerr<<"INVALID_EVIDENCE: "<<e.what()<<"\n"; return 2; }
}
