// ============================================================================
// RAWRXD_REAL_GGUF_PARITY_001
//
// This is deliberately an E2E parity harness over REAL GGUF files.
// It does not contain a model fixture and it does not call another model runner.
//
// Authority model:
//   Pass A: CPU Deep2 reference, deterministic greedy, record full-vocab logits.
//   Pass B: fresh Deep2 instance, strict Vulkan, teacher-force the exact CPU token
//           stream, compare every vocabulary logit and greedy token.
//   Trace : compare production parity-probe checkpoint summaries to localize drift.
//
// Important:
//   CPU-vs-GPU parity proves backend/kernel parity for Deep2's architecture graph.
//   It does NOT by itself prove the architecture graph equals an external reference.
//   The golden file format in this source can also be produced independently and
//   replayed with --verify-golden, preserving no-dependency verification.
// ============================================================================

#include "RealGGUFParity.hpp"
#include "Deep2Engine.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Deep2::Parity {
namespace fs = std::filesystem;

// ------------------------------- SHA-256 -------------------------------------
class Sha256 final {
public:
    Sha256() { reset(); }
    void reset() {
        h_={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
            0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
        bits_=0; used_=0;
    }
    void update(const std::uint8_t* p,std::size_t n) {
        while(n) {
            const std::size_t take=std::min(n,block_.size()-used_);
            std::memcpy(block_.data()+used_,p,take);
            used_+=take; p+=take; n-=take;
            if(used_==64) { transform(block_.data()); bits_+=512; used_=0; }
        }
    }
    std::array<std::uint8_t,32> finish() {
        const std::uint64_t total=bits_+std::uint64_t(used_)*8u;
        block_[used_++]=0x80;
        if(used_>56) { while(used_<64) block_[used_++]=0; transform(block_.data()); used_=0; }
        while(used_<56) block_[used_++]=0;
        for(int i=7;i>=0;--i) block_[used_++]=std::uint8_t(total>>(i*8));
        transform(block_.data());
        std::array<std::uint8_t,32> out{};
        for(std::size_t i=0;i<8;++i) {
            out[i*4+0]=std::uint8_t(h_[i]>>24); out[i*4+1]=std::uint8_t(h_[i]>>16);
            out[i*4+2]=std::uint8_t(h_[i]>>8);  out[i*4+3]=std::uint8_t(h_[i]);
        }
        return out;
    }
private:
    static std::uint32_t rotr(std::uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
    static std::uint32_t ch(std::uint32_t x,std::uint32_t y,std::uint32_t z){return(x&y)^(~x&z);}
    static std::uint32_t maj(std::uint32_t x,std::uint32_t y,std::uint32_t z){return(x&y)^(x&z)^(y&z);}
    static std::uint32_t S0(std::uint32_t x){return rotr(x,2)^rotr(x,13)^rotr(x,22);}
    static std::uint32_t S1(std::uint32_t x){return rotr(x,6)^rotr(x,11)^rotr(x,25);}
    static std::uint32_t s0(std::uint32_t x){return rotr(x,7)^rotr(x,18)^(x>>3);}
    static std::uint32_t s1(std::uint32_t x){return rotr(x,17)^rotr(x,19)^(x>>10);}
    void transform(const std::uint8_t* b) {
        static constexpr std::uint32_t K[64]={
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
        std::uint32_t w[64]{};
        for(int i=0;i<16;++i) w[i]=(std::uint32_t(b[i*4])<<24)|(std::uint32_t(b[i*4+1])<<16)|
                                    (std::uint32_t(b[i*4+2])<<8)|std::uint32_t(b[i*4+3]);
        for(int i=16;i<64;++i) w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
        auto a=h_[0],bb=h_[1],c=h_[2],d=h_[3],e=h_[4],f=h_[5],g=h_[6],hh=h_[7];
        for(int i=0;i<64;++i){const auto t1=hh+S1(e)+ch(e,f,g)+K[i]+w[i];const auto t2=S0(a)+maj(a,bb,c);
            hh=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;}
        h_[0]+=a;h_[1]+=bb;h_[2]+=c;h_[3]+=d;h_[4]+=e;h_[5]+=f;h_[6]+=g;h_[7]+=hh;
    }
    std::array<std::uint32_t,8> h_{};
    std::array<std::uint8_t,64> block_{};
    std::uint64_t bits_=0; std::size_t used_=0;
};

static bool hashFile(const fs::path& p,std::string& hex,std::uint64_t& bytes) {
    std::ifstream f(p,std::ios::binary); if(!f) return false;
    Sha256 s; std::array<char,4u*1024u*1024u> buf{}; bytes=0;
    while(f){f.read(buf.data(),std::streamsize(buf.size()));const auto n=f.gcount();
        if(n>0){s.update(reinterpret_cast<const std::uint8_t*>(buf.data()),std::size_t(n));bytes+=std::uint64_t(n);}}
    const auto d=s.finish(); std::ostringstream o;o<<std::hex<<std::setfill('0');
    for(auto x:d)o<<std::setw(2)<<unsigned(x);hex=o.str();return true;
}

// ------------------------------- Golden I/O ---------------------------------
// Portable little-endian binary format. No structs are dumped directly.
// This lets an independent oracle produce the same file without C++ ABI coupling.
static constexpr char kMagic[16]={'R','A','W','R','P','A','R','I','T','Y','G','0','1',0,0,0};

struct GoldenStep {
    int32_t inputToken=-1;
    int32_t top1=-1;
    std::vector<float> logits;
};

struct Golden {
    std::string modelSha256;
    std::uint64_t modelBytes=0;
    std::string architecture;
    std::string prompt;
    std::vector<int32_t> promptTokens;
    std::vector<GoldenStep> steps;
};

template<class T>
static void writeLE(std::ostream& o,T v) {
    static_assert(std::is_integral_v<T>);
    using U=std::make_unsigned_t<T>;U u=static_cast<U>(v);
    for(std::size_t i=0;i<sizeof(T);++i)o.put(char((u>>(i*8))&0xffu));
}
static void writeF32(std::ostream& o,float v){std::uint32_t u;std::memcpy(&u,&v,4);writeLE(o,u);}
template<class T>
static bool readLE(std::istream& i,T& v) {
    static_assert(std::is_integral_v<T>);
    using U=std::make_unsigned_t<T>;U u=0;
    for(std::size_t b=0;b<sizeof(T);++b){int c=i.get();if(c==EOF)return false;u|=U(std::uint8_t(c))<<(b*8);}
    v=static_cast<T>(u);return true;
}
static bool readF32(std::istream& i,float& v){std::uint32_t u;if(!readLE(i,u))return false;std::memcpy(&v,&u,4);return true;}
static void writeString(std::ostream& o,const std::string& s){writeLE<std::uint64_t>(o,s.size());o.write(s.data(),std::streamsize(s.size()));}
static bool readString(std::istream& i,std::string& s){std::uint64_t n=0;if(!readLE(i,n)||n>(1ull<<31))return false;s.resize(std::size_t(n));return bool(i.read(s.data(),std::streamsize(n)));}

static bool saveGolden(const fs::path& p,const Golden& g,std::string& err) {
    std::ofstream o(p,std::ios::binary|std::ios::trunc);if(!o){err="cannot create golden";return false;}
    o.write(kMagic,sizeof(kMagic));writeLE<std::uint32_t>(o,1);writeLE<std::uint32_t>(o,0x01020304u);
    writeString(o,g.modelSha256);writeLE<std::uint64_t>(o,g.modelBytes);writeString(o,g.architecture);writeString(o,g.prompt);
    writeLE<std::uint64_t>(o,g.promptTokens.size());for(auto t:g.promptTokens)writeLE<std::int32_t>(o,t);
    writeLE<std::uint64_t>(o,g.steps.size());
    for(const auto& s:g.steps){writeLE<std::int32_t>(o,s.inputToken);writeLE<std::int32_t>(o,s.top1);
        writeLE<std::uint64_t>(o,s.logits.size());for(float x:s.logits)writeF32(o,x);}
    if(!o){err="golden write failed";return false;}return true;
}

static bool loadGolden(const fs::path& p,Golden& g,std::string& err) {
    std::ifstream i(p,std::ios::binary);if(!i){err="cannot open golden";return false;}
    char m[16]{};if(!i.read(m,16)||std::memcmp(m,kMagic,16)!=0){err="bad golden magic";return false;}
    std::uint32_t ver=0,endian=0;if(!readLE(i,ver)||!readLE(i,endian)||ver!=1||endian!=0x01020304u){err="unsupported golden version";return false;}
    if(!readString(i,g.modelSha256)||!readLE(i,g.modelBytes)||!readString(i,g.architecture)||!readString(i,g.prompt)){err="golden header truncated";return false;}
    std::uint64_t np=0;if(!readLE(i,np)||np>(1ull<<24)){err="bad prompt token count";return false;}
    g.promptTokens.resize(std::size_t(np));for(auto& t:g.promptTokens)if(!readLE(i,t)){err="golden prompt truncated";return false;}
    std::uint64_t ns=0;if(!readLE(i,ns)||ns>100000){err="bad step count";return false;}
    g.steps.resize(std::size_t(ns));
    for(auto& s:g.steps){std::uint64_t nv=0;if(!readLE(i,s.inputToken)||!readLE(i,s.top1)||!readLE(i,nv)||nv>(1ull<<28)){err="bad golden step";return false;}
        s.logits.resize(std::size_t(nv));for(float& x:s.logits)if(!readF32(i,x)){err="golden logits truncated";return false;}}
    return true;
}

// ------------------------------ comparison ----------------------------------
static bool finiteVec(const std::vector<float>& x){for(float v:x)if(!std::isfinite(v))return false;return true;}
static int32_t argmax(const std::vector<float>& v){
    if(v.empty())return -1;std::size_t k=0;for(std::size_t i=1;i<v.size();++i)if(v[i]>v[k])k=i;return int32_t(k);
}
static std::vector<std::size_t> topK(const std::vector<float>& v,std::size_t k) {
    k=std::min(k,v.size());std::vector<std::size_t> idx(v.size());std::iota(idx.begin(),idx.end(),0);
    std::partial_sort(idx.begin(),idx.begin()+k,idx.end(),[&](auto a,auto b){if(v[a]!=v[b])return v[a]>v[b];return a<b;});
    idx.resize(k);return idx;
}
static StepMetrics compareLogits(std::size_t step,int32_t teacher,const std::vector<float>& a,
                                 const std::vector<float>& b,const Thresholds& t) {
    StepMetrics m;m.step=step;m.teacherToken=teacher;m.cpuTop1=argmax(a);m.gpuTop1=argmax(b);
    if(a.size()!=b.size()||a.empty()||!finiteVec(a)||!finiteVec(b)){m.finite=false;return m;}
    m.finite=true;long double sa2=0,sb2=0,dot=0,se=0,ma=0;
    for(std::size_t i=0;i<a.size();++i){const double da=a[i],db=b[i],d=std::abs(da-db);
        m.maxAbs=std::max(m.maxAbs,d);ma+=d;se+=d*d;
        const double denom=std::max({1.0,std::abs(da),std::abs(db)});m.maxRel=std::max(m.maxRel,d/denom);
        sa2+=da*da;sb2+=db*db;dot+=da*db;}
    m.meanAbs=double(ma/a.size());m.rms=std::sqrt(double(se/a.size()));
    const long double den=std::sqrt(sa2*sb2);m.cosine=den>0?double(dot/den):((sa2==0&&sb2==0)?1.0:0.0);
    const auto ka=topK(a,t.topK),kb=topK(b,t.topK);std::set<std::size_t> s(ka.begin(),ka.end());
    for(auto x:kb)m.topKIntersection+=s.count(x);
    const bool tokenOk=!t.requireTop1Exact||m.cpuTop1==m.gpuTop1;
    const bool topkOk=!t.requireTopKSetExact||m.topKIntersection==std::min(t.topK,a.size());
    m.pass=tokenOk&&topkOk&&m.maxAbs<=t.absMax&&m.maxRel<=t.relMax&&m.rms<=t.rmsMax&&m.cosine>=t.cosineMin;
    return m;
}

// ------------------------------ trace compare -------------------------------
struct TraceRow {
    std::string key;
    std::unordered_map<std::string,std::string> kv;
};
static std::vector<std::string> splitWs(const std::string& s){
    std::vector<std::string> r;std::istringstream is(s);for(std::string x;is>>x;)r.push_back(x);return r;
}
static std::vector<TraceRow> parseTrace(const fs::path& p) {
    std::ifstream f(p);std::vector<TraceRow> out;std::string line;
    while(std::getline(f,line)){
        if(line.empty())continue;TraceRow r;for(auto& tok:splitWs(line)){auto z=tok.find('=');if(z!=std::string::npos)r.kv[tok.substr(0,z)]=tok.substr(z+1);}
        std::ostringstream k;if(auto q=r.kv.find("STEP");q!=r.kv.end())k<<"S"<<q->second;
        if(auto q=r.kv.find("CP");q!=r.kv.end())k<<"|C"<<q->second;
        if(auto q=r.kv.find("LAYER");q!=r.kv.end())k<<"|L"<<q->second;
        r.key=k.str();if(!r.key.empty())out.push_back(std::move(r));
    }return out;
}
static std::optional<double> number(const std::string& s){
    char* e=nullptr;errno=0;double d=std::strtod(s.c_str(),&e);if(errno||e==s.c_str()||*e!='\0'||!std::isfinite(d))return std::nullopt;return d;
}
static bool compareTrace(const fs::path& cpu,const fs::path& gpu,const Thresholds& th,
                         std::size_t& compared,std::size_t& missing,std::size_t& failed) {
    compared=missing=failed=0;const auto a=parseTrace(cpu),b=parseTrace(gpu);
    std::multimap<std::string,const TraceRow*> bm;for(const auto& r:b)bm.emplace(r.key,&r);
    std::unordered_map<std::string,std::size_t> ordinal;
    for(const auto& x:a){
        auto range=bm.equal_range(x.key);const auto ord=ordinal[x.key]++;auto it=range.first;
        for(std::size_t n=0;n<ord&&it!=range.second;++n)++it;
        if(it==range.second){++missing;continue;}++compared;const auto& y=*it->second;
        for(const char* fld:{"COUNT","MIN","MAX","MEAN","L2"}){
            auto ia=x.kv.find(fld),ib=y.kv.find(fld);if(ia==x.kv.end()||ib==y.kv.end())continue;
            if(std::string_view(fld)=="COUNT"){if(ia->second!=ib->second)++failed;continue;}
            auto da=number(ia->second),db=number(ib->second);if(!da||!db){++failed;continue;}
            const double d=std::abs(*da-*db),den=std::max({1.0,std::abs(*da),std::abs(*db)});
            if(d>th.absMax&&d/den>th.relMax)++failed;
        }
    }
    return missing==0&&failed==0&&a.size()==b.size();
}

// ------------------------------ engine pass ---------------------------------
static bool initEngine(Deep2Engine& e,const Config& cfg,bool gpu,Result& r,std::string& err) {
    EngineConfig ec{};ec.maxSeqLen=cfg.maxSeqLen;ec.numThreads=cfg.numThreads;
    if(!e.initialize(ec)){err="initialize failed";return false;}
    e.enableVulkan(gpu);
    e.setVulkanStrictNoCpuFallback(gpu);
    e.enableVerifiedSpeculation(false);
    ModelLoadDiag d;
    if(!e.loadModel(cfg.modelPath,&d)){err="loadModel failed stage="+d.stageName+" message="+d.message;return false;}
    if(r.architecture.empty())r.architecture=e.modelArchitecture();
    else if(r.architecture!=e.modelArchitecture()){err="architecture changed between reference and replay";return false;}
    return true;
}

static bool processInput(Deep2Engine& e,int32_t token,std::size_t pos,
                         std::vector<float>& hidden,std::vector<float>& logits,
                         bool trace) {
    if(trace)e.parityBeginStep(int(pos));
    if(!e.embedToken(token,hidden.data()))return false;
    if(!e.forwardTokenAllLayers(hidden.data(),pos+1))return false;
    if(e.getConfig().useKVCache&&!e.advancePersistentKv())return false;
    e.computeLogits(hidden.data(),logits.data());
    if(trace)e.parityEmitLogitsTop10(logits.data(),logits.size());
    return finiteVec(logits);
}

static bool runCpuReference(const Config& cfg,Result& r,Golden& g,std::string& err) {
    Deep2Engine e;if(!initEngine(e,cfg,false,r,err))return false;
    g.modelSha256=r.modelSha256;g.modelBytes=r.modelBytes;g.architecture=r.architecture;g.prompt=cfg.prompt;
    auto toks=e.tokenize(cfg.prompt);if(toks.empty()){err="prompt tokenized to zero tokens";return false;}
    g.promptTokens.assign(toks.begin(),toks.end());r.promptTokens=g.promptTokens;

    const auto H=e.getConfig().hiddenDim,V=e.getConfig().vocabSize;
    if(!H||!V){err="zero hidden/vocab geometry";return false;}
    std::vector<float> hidden(H),logits(V);
    if(cfg.enableCheckpointTrace)e.enableParityProbe(cfg.cpuTracePath.c_str(),int(toks.size()+cfg.decodeSteps+1));

    std::size_t pos=0;
    for(int t:toks){
        if(!processInput(e,int32_t(t),pos,hidden,logits,cfg.enableCheckpointTrace)){err="CPU prompt forward failed at pos "+std::to_string(pos);return false;}
        ++pos;
    }

    for(std::size_t s=0;s<cfg.decodeSteps;++s){
        GoldenStep gs;gs.inputToken=(s==0?int32_t(toks.back()):g.steps.back().top1);
        gs.top1=argmax(logits);gs.logits=logits;
        if(gs.top1<0){err="CPU argmax failed";return false;}g.steps.push_back(std::move(gs));
        r.teacherTokens.push_back(g.steps.back().top1);
        if(s+1<cfg.decodeSteps){
            if(!processInput(e,g.steps.back().top1,pos,hidden,logits,cfg.enableCheckpointTrace)){err="CPU decode forward failed at step "+std::to_string(s+1);return false;}
            ++pos;
        }
    }
    if(cfg.enableCheckpointTrace)e.disableParityProbe();
    r.cpuReferenceOk=true;return true;
}

static bool runGpuReplay(const Config& cfg,Result& r,const Golden& g,std::string& err) {
    Deep2Engine e;if(!initEngine(e,cfg,true,r,err))return false;
    auto toks=e.tokenize(cfg.prompt);
    std::vector<int32_t> pt(toks.begin(),toks.end());
    if(pt!=g.promptTokens){err="TOKENIZER_PARITY failure: GPU-pass tokenization differs from golden";return false;}
    const auto H=e.getConfig().hiddenDim,V=e.getConfig().vocabSize;
    if(g.steps.empty()||g.steps[0].logits.size()!=V){err="golden vocab size does not match loaded model";return false;}
    std::vector<float> hidden(H),logits(V);
    const auto fb0=e.vulkanGemvFallbackCount(),ok0=e.vulkanGemvSuccessCount();
    if(cfg.enableCheckpointTrace)e.enableParityProbe(cfg.gpuTracePath.c_str(),int(pt.size()+g.steps.size()+1));

    std::size_t pos=0;
    for(auto t:pt){
        if(!processInput(e,t,pos,hidden,logits,cfg.enableCheckpointTrace)){err="GPU prompt forward failed at pos "+std::to_string(pos);return false;}
        ++pos;
    }
    r.steps.clear();r.tokenParity=true;r.logitParity=true;
    for(std::size_t s=0;s<g.steps.size();++s){
        const int32_t teacher=(s==0?pt.back():g.steps[s-1].top1);
        auto m=compareLogits(s,teacher,g.steps[s].logits,logits,cfg.thresholds);
        r.tokenParity &= (m.cpuTop1==m.gpuTop1);
        r.logitParity &= m.pass;
        r.steps.push_back(m);
        if(s+1<g.steps.size()){
            if(!processInput(e,g.steps[s].top1,pos,hidden,logits,cfg.enableCheckpointTrace)){err="GPU teacher-forced decode failed at step "+std::to_string(s+1);return false;}
            ++pos;
        }
    }
    if(cfg.enableCheckpointTrace)e.disableParityProbe();
    r.gpuFallbackDelta=e.vulkanGemvFallbackCount()-fb0;
    r.gpuGemvSuccess=e.vulkanGemvSuccessCount()-ok0;
    r.realGpuForward=e.isRealGpuForward();
    r.gpuStrictViolation=e.vulkanStrictViolation();
    if(cfg.thresholds.requireRealGpu&&!r.realGpuForward){err="strict GPU replay did not prove real GPU forward";return false;}
    if(cfg.thresholds.requireZeroFallback&&(r.gpuFallbackDelta!=0||r.gpuStrictViolation)){err="strict GPU fallback/violation observed";return false;}
    r.gpuReplayOk=true;return true;
}

// ------------------------------- receipt ------------------------------------
static std::string oneLine(std::string s){for(char& c:s)if(c=='\r'||c=='\n'||c=='=')c=' ';if(s.size()>4096)s.resize(4096);return s;}
static void writeReceipt(const Config& c,const Result& r) {
    if(c.receiptPath.empty())return;fs::path p=c.receiptPath;if(p.has_parent_path())fs::create_directories(p.parent_path());
    std::ofstream f(p,std::ios::binary|std::ios::trunc);if(!f)return;
    f<<"=== RAWRXD_REAL_GGUF_PARITY_001 ===\n";
    f<<"MODEL_PATH="<<oneLine(c.modelPath)<<"\nMODEL_SHA256="<<r.modelSha256<<"\nMODEL_FILE_SIZE_BYTES="<<r.modelBytes<<"\n";
    f<<"MODEL_ARCH="<<r.architecture<<"\nPROMPT="<<oneLine(c.prompt)<<"\nPROMPT_TOKEN_COUNT="<<r.promptTokens.size()<<"\n";
    f<<"CPU_REFERENCE="<<(r.cpuReferenceOk?"PASS":"FAIL")<<"\nGPU_REPLAY="<<(r.gpuReplayOk?"PASS":"FAIL")<<"\n";
    f<<"TOKEN_PARITY="<<(r.tokenParity?"PASS":"FAIL")<<"\nLOGIT_PARITY="<<(r.logitParity?"PASS":"FAIL")<<"\n";
    f<<"REAL_GPU_FORWARD="<<(r.realGpuForward?"PASS":"FAIL")<<"\nGPU_GEMV_SUCCESS_DELTA="<<r.gpuGemvSuccess<<"\n";
    f<<"GPU_FALLBACK_DELTA="<<r.gpuFallbackDelta<<"\nGPU_STRICT_VIOLATION="<<(r.gpuStrictViolation?1:0)<<"\n";
    f<<"ABS_MAX_LIMIT="<<c.thresholds.absMax<<"\nREL_MAX_LIMIT="<<c.thresholds.relMax<<"\nRMS_MAX_LIMIT="<<c.thresholds.rmsMax<<"\nCOSINE_MIN="<<c.thresholds.cosineMin<<"\n";
    for(const auto& s:r.steps){
        f<<"STEP_"<<s.step<<"_TEACHER_TOKEN="<<s.teacherToken<<"\n";
        f<<"STEP_"<<s.step<<"_CPU_TOP1="<<s.cpuTop1<<"\nSTEP_"<<s.step<<"_GPU_TOP1="<<s.gpuTop1<<"\n";
        f<<"STEP_"<<s.step<<"_MAX_ABS="<<std::setprecision(12)<<s.maxAbs<<"\n";
        f<<"STEP_"<<s.step<<"_MEAN_ABS="<<s.meanAbs<<"\nSTEP_"<<s.step<<"_RMS="<<s.rms<<"\n";
        f<<"STEP_"<<s.step<<"_MAX_REL="<<s.maxRel<<"\nSTEP_"<<s.step<<"_COSINE="<<s.cosine<<"\n";
        f<<"STEP_"<<s.step<<"_TOPK_INTERSECTION="<<s.topKIntersection<<"\nSTEP_"<<s.step<<"_VERDICT="<<(s.pass?"PASS":"FAIL")<<"\n";
    }
    if(r.checkpointTraceCompared){
        f<<"CHECKPOINT_TRACE="<<(r.checkpointTracePass?"PASS":"FAIL")<<"\nTRACE_LINES_COMPARED="<<r.traceLinesCompared<<"\n";
        f<<"TRACE_LINES_MISSING="<<r.traceLinesMissing<<"\nTRACE_METRIC_FAILURES="<<r.traceMetricFailures<<"\n";
    } else f<<"CHECKPOINT_TRACE=NOT_RUN\n";
    f<<"FAIL_STAGE="<<(r.failStage.empty()?"NONE":oneLine(r.failStage))<<"\nFAIL_MESSAGE="<<oneLine(r.message)<<"\n";
    f<<"VERDICT="<<(r.pass?"PASS":"FAIL")<<"\n";
}

Result RunRealGgufParity(const Config& cfg) {
    Result r;
    auto fail=[&](const char* stage,const std::string& msg){r.failStage=stage;r.message=msg;r.pass=false;writeReceipt(cfg,r);return r;};
    try {
        if(cfg.modelPath.empty())return fail("ARGS","model path is empty");
        if(!fs::is_regular_file(fs::path(cfg.modelPath)))return fail("MODEL","model path is not a regular file");
        if(!hashFile(fs::path(cfg.modelPath),r.modelSha256,r.modelBytes))return fail("MODEL_HASH","SHA-256 failed");

        Golden g;std::string err;
        if(cfg.verifyGoldenOnly) {
            if(cfg.goldenPath.empty())return fail("GOLDEN","--verify-golden requires --golden");
            if(!loadGolden(cfg.goldenPath,g,err))return fail("GOLDEN_LOAD",err);
            if(g.modelSha256!=r.modelSha256||g.modelBytes!=r.modelBytes)return fail("MODEL_ID","golden belongs to a different GGUF");
            r.architecture=g.architecture;r.promptTokens=g.promptTokens;
            r.teacherTokens.clear();for(const auto& s:g.steps)r.teacherTokens.push_back(s.top1);
        } else {
            if(!runCpuReference(cfg,r,g,err))return fail("CPU_REFERENCE",err);
            if(cfg.writeGolden) {
                if(cfg.goldenPath.empty())return fail("GOLDEN_PATH","--write-golden requires --golden");
                if(!saveGolden(cfg.goldenPath,g,err))return fail("GOLDEN_WRITE",err);
            }
        }

        if(g.modelSha256!=r.modelSha256||g.modelBytes!=r.modelBytes)return fail("MODEL_ID","model identity mismatch before GPU replay");
        if(!runGpuReplay(cfg,r,g,err))return fail("GPU_REPLAY",err);

        if(cfg.enableCheckpointTrace&&!cfg.verifyGoldenOnly) {
            r.checkpointTraceCompared=true;
            r.checkpointTracePass=compareTrace(cfg.cpuTracePath,cfg.gpuTracePath,cfg.thresholds,
                                               r.traceLinesCompared,r.traceLinesMissing,r.traceMetricFailures);
        }

        bool steps=true;for(const auto& s:r.steps)steps&=s.pass;
        r.pass=r.cpuReferenceOk||cfg.verifyGoldenOnly;
        r.pass=r.pass&&r.gpuReplayOk&&r.tokenParity&&r.logitParity&&steps;
        if(cfg.enableCheckpointTrace&&!cfg.verifyGoldenOnly)r.pass=r.pass&&r.checkpointTracePass;
        if(!r.pass&&!r.failStage.size()){r.failStage="PARITY";r.message="one or more parity requirements failed";}
        writeReceipt(cfg,r);return r;
    } catch(const std::exception& e){return fail("EXCEPTION",e.what());}
    catch(...){return fail("UNKNOWN_EXCEPTION","unknown failure");}
}

// ---------------------------------- CLI -------------------------------------
static bool parseSize(const char* s,std::size_t& out){if(!s)return false;std::uint64_t v=0;auto [p,ec]=std::from_chars(s,s+std::strlen(s),v);if(ec!=std::errc{}||*p)return false;out=std::size_t(v);return true;}
static bool parseDouble(const char* s,double& out){if(!s)return false;char* e=nullptr;errno=0;out=std::strtod(s,&e);return !errno&&e!=s&&*e=='\0'&&std::isfinite(out);}

int RunRealGgufParityCli(int argc,char** argv) {
    Config c;
    for(int i=1;i<argc;++i){
        std::string a=argv[i];
        auto value=[&](const char* name)->const char*{if(i+1>=argc)throw std::runtime_error(std::string(name)+" requires value");return argv[++i];};
        if(a=="--model")c.modelPath=value("--model");
        else if(a=="--prompt")c.prompt=value("--prompt");
        else if(a=="--steps"){if(!parseSize(value("--steps"),c.decodeSteps))throw std::runtime_error("bad --steps");}
        else if(a=="--max-seq"){if(!parseSize(value("--max-seq"),c.maxSeqLen))throw std::runtime_error("bad --max-seq");}
        else if(a=="--threads"){if(!parseSize(value("--threads"),c.numThreads))throw std::runtime_error("bad --threads");}
        else if(a=="--receipt")c.receiptPath=value("--receipt");
        else if(a=="--cpu-trace")c.cpuTracePath=value("--cpu-trace");
        else if(a=="--gpu-trace")c.gpuTracePath=value("--gpu-trace");
        else if(a=="--golden")c.goldenPath=value("--golden");
        else if(a=="--write-golden")c.writeGolden=true;
        else if(a=="--verify-golden")c.verifyGoldenOnly=true;
        else if(a=="--no-trace")c.enableCheckpointTrace=false;
        else if(a=="--allow-fallback")c.thresholds.requireZeroFallback=false;
        else if(a=="--allow-no-real-gpu")c.thresholds.requireRealGpu=false;
        else if(a=="--topk"){if(!parseSize(value("--topk"),c.thresholds.topK))throw std::runtime_error("bad --topk");}
        else if(a=="--abs"){if(!parseDouble(value("--abs"),c.thresholds.absMax))throw std::runtime_error("bad --abs");}
        else if(a=="--rel"){if(!parseDouble(value("--rel"),c.thresholds.relMax))throw std::runtime_error("bad --rel");}
        else if(a=="--rms"){if(!parseDouble(value("--rms"),c.thresholds.rmsMax))throw std::runtime_error("bad --rms");}
        else if(a=="--cosine"){if(!parseDouble(value("--cosine"),c.thresholds.cosineMin))throw std::runtime_error("bad --cosine");}
        else if(a=="--topk-exact")c.thresholds.requireTopKSetExact=true;
        else if(a=="--help"||a=="-h"){
            std::printf(
                "rawrxd_real_gguf_parity --model MODEL.gguf [options]\n"
                "  --prompt TEXT       deterministic prompt\n"
                "  --steps N           greedy teacher-forced decode steps (default 8)\n"
                "  --abs X --rel X --rms X --cosine X\n"
                "  --topk N [--topk-exact]\n"
                "  --receipt FILE --cpu-trace FILE --gpu-trace FILE\n"
                "  --golden FILE --write-golden\n"
                "  --golden FILE --verify-golden   (skip CPU pass; verify independent golden)\n"
                "  --no-trace --allow-fallback --allow-no-real-gpu\n");
            return 0;
        } else throw std::runtime_error("unknown argument: "+a);
    }
    if(c.modelPath.empty()){std::fprintf(stderr,"ERROR: --model is required\n");return 2;}
    try {
        auto r=RunRealGgufParity(c);
        std::printf("RAWRXD_REAL_GGUF_PARITY_001=%s\n",r.pass?"PASS":"FAIL");
        std::printf("MODEL_ARCH=%s\nMODEL_SHA256=%s\n",r.architecture.c_str(),r.modelSha256.c_str());
        std::printf("TOKEN_PARITY=%s\nLOGIT_PARITY=%s\n",r.tokenParity?"PASS":"FAIL",r.logitParity?"PASS":"FAIL");
        std::printf("REAL_GPU_FORWARD=%s\nGPU_FALLBACK_DELTA=%llu\n",r.realGpuForward?"PASS":"FAIL",(unsigned long long)r.gpuFallbackDelta);
        if(!r.pass)std::printf("FAIL_STAGE=%s\nFAIL_MESSAGE=%s\n",r.failStage.c_str(),r.message.c_str());
        return r.pass?0:1;
    } catch(const std::exception& e){std::fprintf(stderr,"ERROR: %s\n",e.what());return 2;}
}

} // namespace Deep2::Parity
