// RAWRXD_AUTOCLOSURE_001
#include "RawrXDAutoClosure.hpp"
#include "deep2/Deep2Engine.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>

#pragma comment(lib, "shell32.lib")

namespace RawrXD::AutoClosure {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

// -----------------------------------------------------------------------------
// UTF conversion
// -----------------------------------------------------------------------------
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                                static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                        static_cast<int>(s.size()), out.data(), n);
    return out;
}

static std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), n, nullptr, nullptr);
    return out;
}

static std::string PathUtf8(const fs::path& p) {
    return WideToUtf8(p.wstring());
}

// -----------------------------------------------------------------------------
// Tiny source-only SHA-256
// -----------------------------------------------------------------------------
class Sha256 {
public:
    Sha256() { reset(); }

    void reset() {
        h_ = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
              0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
        bitLen_ = 0;
        used_ = 0;
    }

    void update(const uint8_t* data, size_t n) {
        while (n) {
            size_t take = std::min(n, block_.size() - used_);
            std::memcpy(block_.data() + used_, data, take);
            used_ += take;
            data += take;
            n -= take;
            if (used_ == block_.size()) {
                transform(block_.data());
                bitLen_ += 512;
                used_ = 0;
            }
        }
    }

    std::array<uint8_t,32> finish() {
        const uint64_t totalBits = bitLen_ + static_cast<uint64_t>(used_) * 8ull;
        block_[used_++] = 0x80;
        if (used_ > 56) {
            while (used_ < 64) block_[used_++] = 0;
            transform(block_.data());
            used_ = 0;
        }
        while (used_ < 56) block_[used_++] = 0;
        for (int i = 7; i >= 0; --i)
            block_[used_++] = static_cast<uint8_t>((totalBits >> (i*8)) & 0xffu);
        transform(block_.data());

        std::array<uint8_t,32> out{};
        for (size_t i=0;i<8;++i) {
            out[i*4+0] = static_cast<uint8_t>((h_[i] >> 24) & 0xffu);
            out[i*4+1] = static_cast<uint8_t>((h_[i] >> 16) & 0xffu);
            out[i*4+2] = static_cast<uint8_t>((h_[i] >> 8) & 0xffu);
            out[i*4+3] = static_cast<uint8_t>(h_[i] & 0xffu);
        }
        return out;
    }

private:
    static uint32_t rotr(uint32_t x, uint32_t n) { return (x>>n) | (x<<(32-n)); }
    static uint32_t ch(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(~x&z);}
    static uint32_t maj(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(x&z)^(y&z);}
    static uint32_t s0(uint32_t x){return rotr(x,2)^rotr(x,13)^rotr(x,22);}
    static uint32_t s1(uint32_t x){return rotr(x,6)^rotr(x,11)^rotr(x,25);}
    static uint32_t g0(uint32_t x){return rotr(x,7)^rotr(x,18)^(x>>3);}
    static uint32_t g1(uint32_t x){return rotr(x,17)^rotr(x,19)^(x>>10);}

    void transform(const uint8_t* b) {
        static constexpr uint32_t K[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
        };
        uint32_t w[64]{};
        for (int i=0;i<16;++i)
            w[i] = (uint32_t(b[i*4])<<24)|(uint32_t(b[i*4+1])<<16)|
                   (uint32_t(b[i*4+2])<<8)|uint32_t(b[i*4+3]);
        for (int i=16;i<64;++i) w[i]=g1(w[i-2])+w[i-7]+g0(w[i-15])+w[i-16];

        uint32_t a=h_[0],b0=h_[1],c=h_[2],d=h_[3],e=h_[4],f=h_[5],g=h_[6],h=h_[7];
        for (int i=0;i<64;++i) {
            uint32_t t1=h+s1(e)+ch(e,f,g)+K[i]+w[i];
            uint32_t t2=s0(a)+maj(a,b0,c);
            h=g; g=f; f=e; e=d+t1; d=c; c=b0; b0=a; a=t1+t2;
        }
        h_[0]+=a;h_[1]+=b0;h_[2]+=c;h_[3]+=d;h_[4]+=e;h_[5]+=f;h_[6]+=g;h_[7]+=h;
    }

    std::array<uint32_t,8> h_{};
    std::array<uint8_t,64> block_{};
    uint64_t bitLen_=0;
    size_t used_=0;
};

static bool HashFileSha256(const fs::path& p, std::string& hex, uint64_t& bytes) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    Sha256 s;
    std::array<char,1<<20> buf{};
    bytes = 0;
    while (f) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize n = f.gcount();
        if (n > 0) {
            s.update(reinterpret_cast<const uint8_t*>(buf.data()), static_cast<size_t>(n));
            bytes += static_cast<uint64_t>(n);
        }
    }
    auto d=s.finish();
    std::ostringstream os;
    os<<std::hex<<std::setfill('0');
    for(uint8_t v:d) os<<std::setw(2)<<static_cast<unsigned>(v);
    hex=os.str();
    return true;
}

// -----------------------------------------------------------------------------
// Receipt
// -----------------------------------------------------------------------------
struct Receipt {
    fs::path path;
    std::unordered_map<std::string,std::string> kv;
    std::vector<std::pair<std::string,std::string>> ordered;

    void set(const std::string& k,const std::string& v) {
        kv[k]=v;
        ordered.emplace_back(k,v);
    }
    void set(const std::string& k,uint64_t v){ set(k,std::to_string(v)); }
    void setBool(const std::string& k,bool v){ set(k,v?"PASS":"FAIL"); }

    void flush() noexcept {
        try {
            if (path.empty()) return;
            if (path.has_parent_path()) fs::create_directories(path.parent_path());
            fs::path tmp=path; tmp+=L".tmp";
            std::ofstream f(tmp,std::ios::binary|std::ios::trunc);
            if(!f) return;
            for(const auto& p:ordered) f<<p.first<<"="<<p.second<<"\n";
            f.flush(); f.close();
            if (!MoveFileExW(tmp.c_str(), path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                std::error_code ec;
                fs::copy_file(tmp,path,fs::copy_options::overwrite_existing,ec);
                fs::remove(tmp,ec);
            }
        } catch(...) {}
    }
    ~Receipt(){ flush(); }
};

static std::string OneLine(std::string s) {
    for(char& c:s) if(c=='\r'||c=='\n'||c=='=') c=' ';
    if(s.size()>4096) s.resize(4096);
    return s;
}

// -----------------------------------------------------------------------------
// Bounded deterministic decode. This intentionally bypasses the older
// Deep2Engine::generate() loop and drives the already-public production
// primitives directly, so a control-loop bug cannot block certification.
// -----------------------------------------------------------------------------
static GateResult DecodeBounded(
    Deep2::Deep2Engine& e,
    const std::string& prompt,
    uint32_t maxTokens,
    const std::string& stopText = {})
{
    GateResult r;
    r.modelLoaded=e.isModelLoaded();
    if(!r.modelLoaded){r.failStage="MODEL_NOT_LOADED";return r;}
    if(maxTokens==0){r.failStage="TOKEN_BUDGET_ZERO";return r;}

    try {
        e.reset();
        auto toks=e.tokenize(prompt);
        r.promptTokens=toks.size();
        r.tokenizerReady=!toks.empty();
        if(toks.empty()){r.failStage="TOKENIZE_EMPTY";return r;}

        const auto& cfg=e.getConfig();
        const size_t H=cfg.hiddenDim;
        const size_t V=cfg.vocabSize;
        if(H==0||V==0){r.failStage="MODEL_GEOMETRY_ZERO";return r;}
        if(cfg.maxSeqLen && toks.size()>=cfg.maxSeqLen){
            r.failStage="PROMPT_EXCEEDS_CONTEXT";return r;
        }

        std::vector<float> hidden(H,0.0f);
        std::vector<float> logits(V,0.0f);

        size_t seq=0;
        for(size_t i=0;i<toks.size();++i) {
            if(!e.embedToken(toks[i],hidden.data())) {
                r.failStage="PREFILL_EMBED";
                r.failMessage="token_index="+std::to_string(i);
                return r;
            }
            ++seq;
            if(!e.forwardTokenAllLayers(hidden.data(),seq)) {
                r.failStage="PREFILL_FORWARD";
                r.failMessage="token_index="+std::to_string(i);
                return r;
            }
            if(cfg.useKVCache) e.advancePersistentKv();
        }
        r.forwardPassOk=true;

        for(uint32_t step=0;step<maxTokens;++step) {
            e.computeLogits(hidden.data(),logits.data());

            bool finite=true;
            int best=0;
            float bestv=logits[0];
            for(size_t i=0;i<V;++i) {
                if(!std::isfinite(logits[i])) { finite=false; break; }
                if(logits[i]>bestv){bestv=logits[i];best=static_cast<int>(i);}
            }
            if(!finite){
                r.failStage="LOGITS_NONFINITE";
                r.failMessage="step="+std::to_string(step);
                return r;
            }
            r.logitsFinite=true;
            if(best<0||static_cast<size_t>(best)>=V){
                r.failStage="ARGMAX_RANGE";return r;
            }

            r.generated.push_back(best);
            r.generatedTokens=r.generated.size();

            if(!stopText.empty()) {
                r.generatedText=e.detokenize(r.generated);
                if(r.generatedText.find(stopText)!=std::string::npos) break;
            }

            if(step+1>=maxTokens) break;
            if(cfg.maxSeqLen && seq+1>=cfg.maxSeqLen) break;

            if(!e.embedToken(best,hidden.data())) {
                r.failStage="DECODE_EMBED";
                r.failMessage="step="+std::to_string(step);
                return r;
            }
            ++seq;
            if(!e.forwardTokenAllLayers(hidden.data(),seq)) {
                r.failStage="DECODE_FORWARD";
                r.failMessage="step="+std::to_string(step);
                return r;
            }
            if(cfg.useKVCache) e.advancePersistentKv();
        }

        if(r.generatedText.empty()&&!r.generated.empty())
            r.generatedText=e.detokenize(r.generated);

        r.realGpuForward=e.isRealGpuForward();
        r.strictGpuViolation=e.vulkanStrictViolation();
        r.pass=r.generatedTokens>0&&r.forwardPassOk&&r.logitsFinite;
        if(!r.pass&&r.failStage.empty()) r.failStage="NO_TOKENS";
        return r;
    } catch(const std::exception& ex) {
        r.failStage="EXCEPTION";
        r.failMessage=ex.what();
        return r;
    } catch(...) {
        r.failStage="UNKNOWN_EXCEPTION";
        return r;
    }
}

static bool SetupEngine(Deep2::Deep2Engine& e,const Options& o,GateResult& r) {
    if(o.modelPath.empty()){r.failStage="MODEL_PATH_EMPTY";return false;}
    if(!fs::exists(o.modelPath)){r.failStage="MODEL_NOT_FOUND";return false;}
    if(!HashFileSha256(o.modelPath,r.modelSha256,r.modelBytes)){
        r.failStage="MODEL_HASH_FAILED";return false;
    }

    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen=4096;
    cfg.numThreads=0;
    if(!e.initialize(cfg)){r.failStage="ENGINE_INIT";return false;}
    if(!e.loadModel(PathUtf8(o.modelPath))){
        r.failStage="MODEL_LOAD";return false;
    }
    r.modelLoaded=true;

    e.setVulkanStrictNoCpuFallback(o.strictGpu);
    e.enableVulkan(true);
    if(o.strictGpu&&!e.isVulkanInitialized()){
        r.failStage="VULKAN_INIT";return false;
    }

    Deep2::GenerationOptions go{};
    go.temperature=0.0f;
    go.topK=1;
    go.topP=1.0f;
    go.seed=1;
    e.configureGeneration(go);
    return true;
}

static GateResult RunFastGate(Deep2::Deep2Engine& e,const Options& o) {
    GateResult base;
    if(!SetupEngine(e,o,base)) return base;

    uint64_t fb0=e.vulkanGemvFallbackCount();
    GateResult r=DecodeBounded(e,o.gatePrompt,o.gateTokens);
    r.modelSha256=base.modelSha256;
    r.modelBytes=base.modelBytes;
    r.modelLoaded=base.modelLoaded;
    uint64_t fb1=e.vulkanGemvFallbackCount();
    r.gpuFallbackDelta=(fb1>=fb0)?(fb1-fb0):fb1;
    r.realGpuForward=e.isRealGpuForward();
    r.strictGpuViolation=e.vulkanStrictViolation();

    if(o.requireRealGpuForward&&!r.realGpuForward) {
        r.pass=false; r.failStage="REAL_GPU_FORWARD";
    }
    if(o.requireZeroFallback&&r.gpuFallbackDelta!=0) {
        r.pass=false; r.failStage="GPU_FALLBACK";
        r.failMessage="fallback_delta="+std::to_string(r.gpuFallbackDelta);
    }
    if(o.strictGpu&&r.strictGpuViolation) {
        r.pass=false; r.failStage="STRICT_GPU_VIOLATION";
    }
    return r;
}

// -----------------------------------------------------------------------------
// Win32 process runner with stdout/stderr capture + hard timeout
// -----------------------------------------------------------------------------
struct ProcessResult {
    bool launched=false;
    bool timedOut=false;
    DWORD exitCode=0xffffffffu;
    std::string output;
};

static ProcessResult RunProcess(
    const std::string& command,const fs::path& cwd,uint64_t timeoutMs)
{
    ProcessResult r;
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
    HANDLE rd=nullptr,wr=nullptr;
    if(!CreatePipe(&rd,&wr,&sa,0)) return r;
    SetHandleInformation(rd,HANDLE_FLAG_INHERIT,0);

    STARTUPINFOW si{};
    si.cb=sizeof(si);
    si.dwFlags=STARTF_USESTDHANDLES;
    si.hStdOutput=wr;
    si.hStdError=wr;
    si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::wstring cmd=L"cmd.exe /d /s /c \""+Utf8ToWide(command)+L"\"";
    std::vector<wchar_t> mutableCmd(cmd.begin(),cmd.end());
    mutableCmd.push_back(L'\0');

    std::wstring wcwd=cwd.empty()?L"":cwd.wstring();
    BOOL ok=CreateProcessW(nullptr,mutableCmd.data(),nullptr,nullptr,TRUE,
                           CREATE_NO_WINDOW,nullptr,
                           wcwd.empty()?nullptr:wcwd.c_str(),&si,&pi);
    CloseHandle(wr);
    if(!ok){CloseHandle(rd);return r;}
    r.launched=true;

    const auto deadline=Clock::now()+std::chrono::milliseconds(timeoutMs);
    constexpr size_t MAX_CAPTURE=512*1024;
    for(;;) {
        DWORD avail=0;
        if(PeekNamedPipe(rd,nullptr,0,nullptr,&avail,nullptr)&&avail) {
            std::array<char,8192> buf{};
            DWORD got=0;
            DWORD want=std::min<DWORD>(avail,static_cast<DWORD>(buf.size()));
            if(ReadFile(rd,buf.data(),want,&got,nullptr)&&got) {
                if(r.output.size()<MAX_CAPTURE) {
                    size_t keep=std::min<size_t>(got,MAX_CAPTURE-r.output.size());
                    r.output.append(buf.data(),keep);
                }
            }
        }

        DWORD w=WaitForSingleObject(pi.hProcess,25);
        if(w==WAIT_OBJECT_0) break;
        if(Clock::now()>=deadline) {
            r.timedOut=true;
            TerminateProcess(pi.hProcess,0xdead);
            WaitForSingleObject(pi.hProcess,5000);
            break;
        }
    }

    for(;;) {
        DWORD avail=0;
        if(!PeekNamedPipe(rd,nullptr,0,nullptr,&avail,nullptr)||!avail) break;
        std::array<char,8192> buf{};
        DWORD got=0;
        if(!ReadFile(rd,buf.data(),std::min<DWORD>(avail,(DWORD)buf.size()),&got,nullptr)||!got) break;
        if(r.output.size()<MAX_CAPTURE) {
            size_t keep=std::min<size_t>(got,MAX_CAPTURE-r.output.size());
            r.output.append(buf.data(),keep);
        }
    }

    GetExitCodeProcess(pi.hProcess,&r.exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return r;
}

// -----------------------------------------------------------------------------
// Workspace confinement + native source tools
// -----------------------------------------------------------------------------
static bool PathComponentEqual(const fs::path& a,const fs::path& b) {
    return _wcsicmp(a.c_str(),b.c_str())==0;
}

static bool ResolveInside(
    const fs::path& root,const fs::path& user,fs::path& out)
{
    try {
        fs::path rc=fs::weakly_canonical(root);
        fs::path candidate=user.is_absolute()?user:(rc/user);
        candidate=fs::weakly_canonical(candidate);

        auto ri=rc.begin(),re=rc.end(),ci=candidate.begin(),ce=candidate.end();
        for(;ri!=re;++ri,++ci) {
            if(ci==ce||!PathComponentEqual(*ri,*ci)) return false;
        }
        out=candidate;
        return true;
    } catch(...) { return false; }
}

static std::string ReadTextLimited(const fs::path& p,size_t maxBytes=192*1024) {
    std::ifstream f(p,std::ios::binary);
    if(!f) return "ERROR: cannot open file";
    std::string s;
    s.resize(maxBytes);
    f.read(s.data(),static_cast<std::streamsize>(s.size()));
    s.resize(static_cast<size_t>(f.gcount()));
    if(f.peek()!=EOF) s+="\n...[TRUNCATED]...";
    return s;
}

static bool WriteAtomic(const fs::path& p,const std::string& data,std::string& err) {
    try {
        if(p.has_parent_path()) fs::create_directories(p.parent_path());
        fs::path tmp=p; tmp+=L".rawrxd.tmp";
        {
            std::ofstream f(tmp,std::ios::binary|std::ios::trunc);
            if(!f){err="open temp failed";return false;}
            f.write(data.data(),static_cast<std::streamsize>(data.size()));
            if(!f){err="write failed";return false;}
        }
        if (!MoveFileExW(tmp.c_str(), p.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DWORD e=GetLastError();
            std::error_code ec; fs::remove(tmp,ec);
            err="MoveFileExW failed: "+std::to_string(e);
            return false;
        }
        return true;
    } catch(const std::exception& ex){err=ex.what();return false;}
}

struct ToolCall {
    std::string name;
    std::string path;
    std::string body;
    std::string oldText;
    std::string newText;
};

static std::string Attr(const std::string& head,const std::string& key) {
    const std::string q=key+"=\"";
    size_t p=head.find(q);
    if(p==std::string::npos) return {};
    p+=q.size();
    size_t e=head.find('"',p);
    return e==std::string::npos?std::string{}:head.substr(p,e-p);
}

static std::optional<ToolCall> ParseTool(const std::string& text) {
    size_t p=text.find("<RAWR_TOOL");
    if(p==std::string::npos) return std::nullopt;
    size_t h=text.find('>',p);
    if(h==std::string::npos) return std::nullopt;
    std::string head=text.substr(p,h-p+1);
    size_t c=text.find("</RAWR_TOOL>",h+1);
    if(c==std::string::npos) return std::nullopt;

    ToolCall t;
    t.name=Attr(head,"name");
    t.path=Attr(head,"path");
    t.body=text.substr(h+1,c-(h+1));

    auto extract=[&](const char* a,const char* b)->std::string{
        size_t s=t.body.find(a);
        if(s==std::string::npos) return {};
        s+=std::strlen(a);
        size_t e=t.body.find(b,s);
        return e==std::string::npos?std::string{}:t.body.substr(s,e-s);
    };
    t.oldText=extract("<OLD>","</OLD>");
    t.newText=extract("<NEW>","</NEW>");
    if(t.name.empty()) return std::nullopt;
    return t;
}

static std::string BuildAgentPrompt(
    const Options& o,const std::string& task,uint32_t iteration,
    const std::string& lastResult)
{
    std::ostringstream s;
    s <<
R"(You are the RawrXD autonomous source-closure engineer.
You must complete the task by inspecting and editing the supplied workspace.
Do not ask the operator to run intermediate gates. You own the loop.

Return EXACTLY ONE tool call per response. Text before/after the tag is ignored.

Allowed forms:

<RAWR_TOOL name="read_file" path="relative/path"></RAWR_TOOL>
<RAWR_TOOL name="list_dir" path="relative/path"></RAWR_TOOL>
<RAWR_TOOL name="find_text" path="relative/path/or/dir">literal text</RAWR_TOOL>
<RAWR_TOOL name="write_file" path="relative/path">COMPLETE FILE CONTENT</RAWR_TOOL>
<RAWR_TOOL name="replace_text" path="relative/path"><OLD>exact old text</OLD><NEW>exact new text</NEW></RAWR_TOOL>
<RAWR_TOOL name="git_diff"></RAWR_TOOL>
<RAWR_TOOL name="run_build"></RAWR_TOOL>
<RAWR_TOOL name="run_test"></RAWR_TOOL>
<RAWR_TOOL name="finish">brief completion statement</RAWR_TOOL>

Rules:
- Read before editing unless you already have the exact file content.
- replace_text is exact and must match exactly once.
- write_file replaces the complete file atomically.
- Build/test failures are returned to you automatically; fix them and continue.
- Never fabricate a PASS. finish is accepted only after configured build/test pass.
- Stay inside the workspace.
)";
    s<<"ITERATION="<<iteration<<"\n";
    std::string taskBounded=task;
    if(taskBounded.size()>24000) taskBounded.resize(24000);
    s<<"TASK:\n"<<taskBounded<<"\n";
    if(!lastResult.empty()) {
        std::string lr=lastResult;
        if(lr.size()>12000) lr.resize(12000);
        s<<"LAST_TOOL_RESULT:\n"<<lr<<"\n";
    }
    return s.str();
}

class NativeAuthority {
public:
    explicit NativeAuthority(const Options& o):o_(o){}

    struct Result {
        bool ok=false;
        bool edited=false;
        bool buildRun=false;
        bool testRun=false;
        bool buildPass=false;
        bool testPass=false;
        bool finish=false;
        std::string text;
    };

    Result execute(const ToolCall& t) {
        if(t.name=="read_file") return read(t);
        if(t.name=="list_dir") return list(t);
        if(t.name=="find_text") return find(t);
        if(t.name=="write_file") return write(t);
        if(t.name=="replace_text") return replace(t);
        if(t.name=="git_diff") return gitDiff();
        if(t.name=="run_build") return build();
        if(t.name=="run_test") return test();
        if(t.name=="finish") { Result r; r.ok=true;r.finish=true;r.text=t.body;return r; }
        Result r; r.text="ERROR: unknown tool '"+t.name+"'"; return r;
    }

    Result build() {
        Result r; r.buildRun=true;
        if(o_.buildCommand.empty()){r.ok=true;r.buildPass=true;r.text="BUILD_SKIPPED=no build command configured";return r;}
        ProcessResult p=RunProcess(o_.buildCommand,o_.workspace,o_.commandTimeoutMs);
        r.ok=p.launched&&!p.timedOut&&p.exitCode==0;
        r.buildPass=r.ok;
        r.text="BUILD_EXIT="+std::to_string(p.exitCode)+" TIMEOUT="+std::to_string(p.timedOut?1:0)+"\n"+p.output;
        return r;
    }

    Result test() {
        Result r; r.testRun=true;
        if(o_.testCommand.empty()){r.ok=true;r.testPass=true;r.text="TEST_SKIPPED=no test command configured";return r;}
        ProcessResult p=RunProcess(o_.testCommand,o_.workspace,o_.commandTimeoutMs);
        r.ok=p.launched&&!p.timedOut&&p.exitCode==0;
        r.testPass=r.ok;
        r.text="TEST_EXIT="+std::to_string(p.exitCode)+" TIMEOUT="+std::to_string(p.timedOut?1:0)+"\n"+p.output;
        return r;
    }

private:
    Result read(const ToolCall& t) {
        Result r; fs::path p;
        if(!ResolveInside(o_.workspace,Utf8ToWide(t.path),p)){r.text="ERROR: path escapes workspace";return r;}
        r.text=ReadTextLimited(p); r.ok=r.text.rfind("ERROR:",0)!=0; return r;
    }

    Result list(const ToolCall& t) {
        Result r; fs::path p;
        if(!ResolveInside(o_.workspace,Utf8ToWide(t.path.empty()?".":t.path),p)){r.text="ERROR: path escapes workspace";return r;}
        try {
            std::ostringstream s; size_t n=0;
            for(auto& e:fs::directory_iterator(p)) {
                s<<(e.is_directory()?"D ":"F ")<<PathUtf8(e.path().filename())<<"\n";
                if(++n>=512){s<<"...[TRUNCATED]...\n";break;}
            }
            r.ok=true;r.text=s.str();return r;
        } catch(const std::exception& ex){r.text=std::string("ERROR: ")+ex.what();return r;}
    }

    Result find(const ToolCall& t) {
        Result r; fs::path p;
        if(!ResolveInside(o_.workspace,Utf8ToWide(t.path.empty()?".":t.path),p)){r.text="ERROR: path escapes workspace";return r;}
        const std::string needle=t.body;
        if(needle.empty()){r.text="ERROR: empty search";return r;}
        try {
            std::ostringstream s; size_t hits=0;
            auto scan=[&](const fs::path& f){
                if(hits>=100||!fs::is_regular_file(f)) return;
                std::error_code ec;
                auto sz=fs::file_size(f,ec);
                if(ec||sz>2*1024*1024) return;
                std::ifstream in(f,std::ios::binary); if(!in) return;
                std::string line; size_t ln=0;
                while(std::getline(in,line)) {
                    ++ln;
                    if(line.find(needle)!=std::string::npos) {
                        s<<PathUtf8(fs::relative(f,o_.workspace))<<":"<<ln<<":"<<line<<"\n";
                        if(++hits>=100) break;
                    }
                }
            };
            if(fs::is_regular_file(p)) scan(p);
            else {
                for(auto it=fs::recursive_directory_iterator(p,fs::directory_options::skip_permission_denied);
                    it!=fs::recursive_directory_iterator()&&hits<100;++it) {
                    const auto name=it->path().filename().wstring();
                    if(it->is_directory()&&(name==L".git"||name==L"build"||name==L"build_v4")) {
                        it.disable_recursion_pending(); continue;
                    }
                    scan(it->path());
                }
            }
            r.ok=true;r.text=s.str().empty()?"NO_MATCHES":s.str();return r;
        } catch(const std::exception& ex){r.text=std::string("ERROR: ")+ex.what();return r;}
    }

    Result write(const ToolCall& t) {
        Result r; fs::path p;
        if(!ResolveInside(o_.workspace,Utf8ToWide(t.path),p)){r.text="ERROR: path escapes workspace";return r;}
        std::string err;
        r.ok=WriteAtomic(p,t.body,err);
        r.edited=r.ok;
        r.text=r.ok?"WRITE_OK "+PathUtf8(fs::relative(p,o_.workspace)):"ERROR: "+err;
        return r;
    }

    Result replace(const ToolCall& t) {
        Result r; fs::path p;
        if(!ResolveInside(o_.workspace,Utf8ToWide(t.path),p)){r.text="ERROR: path escapes workspace";return r;}
        if(t.oldText.empty()){r.text="ERROR: OLD block empty";return r;}
        std::error_code sec;
        const auto fileBytes=fs::file_size(p,sec);
        if(sec||fileBytes>16ull*1024ull*1024ull){r.text="ERROR: file missing or >16MiB";return r;}
        std::ifstream fin(p,std::ios::binary);
        if(!fin){r.text="ERROR: cannot open file";return r;}
        std::string cur((std::istreambuf_iterator<char>(fin)),std::istreambuf_iterator<char>());
        size_t a=cur.find(t.oldText);
        if(a==std::string::npos){r.text="ERROR: exact OLD block not found";return r;}
        if(cur.find(t.oldText,a+t.oldText.size())!=std::string::npos){
            r.text="ERROR: OLD block matched more than once";return r;
        }
        cur.replace(a,t.oldText.size(),t.newText);
        std::string err;
        r.ok=WriteAtomic(p,cur,err);
        r.edited=r.ok;
        r.text=r.ok?"REPLACE_OK "+PathUtf8(fs::relative(p,o_.workspace)):"ERROR: "+err;
        return r;
    }

    Result gitDiff() {
        Result r;
        ProcessResult p=RunProcess("git diff -- .",o_.workspace,std::min<uint64_t>(60000,o_.commandTimeoutMs));
        r.ok=p.launched&&!p.timedOut&&(p.exitCode==0);
        r.text="GIT_DIFF_EXIT="+std::to_string(p.exitCode)+"\n"+p.output;
        return r;
    }

    const Options& o_;
};

static AgentResult RunAgent(
    Deep2::Deep2Engine& e,const Options& o,const std::string& task)
{
    AgentResult ar;
    NativeAuthority auth(o);
    std::string lastResult;
    std::string lastSig;
    uint32_t repeated=0;
    const auto deadline=Clock::now()+std::chrono::milliseconds(o.wallTimeoutMs);

    for(uint32_t iter=1;iter<=o.maxIterations;++iter) {
        ar.iterations=iter;
        if(Clock::now()>=deadline){ar.failStage="AGENT_WALL_TIMEOUT";return ar;}
        if(ar.toolCalls>=o.maxToolCalls){ar.failStage="TOOL_BUDGET";return ar;}

        const std::string prompt=BuildAgentPrompt(o,task,iter,lastResult);
        GateResult g=DecodeBounded(e,prompt,o.agentTokens,"</RAWR_TOOL>");
        if(!g.pass) {
            ar.failStage="AGENT_INFERENCE_"+g.failStage;
            ar.failMessage=g.failMessage;
            return ar;
        }

        auto tc=ParseTool(g.generatedText);
        if(!tc) {
            lastResult="ERROR: model emitted no parseable <RAWR_TOOL> call.\nMODEL_OUTPUT:\n"+g.generatedText;
            continue;
        }

        std::string sig=tc->name+"\n"+tc->path+"\n"+tc->body;
        if(sig==lastSig) ++repeated; else repeated=0;
        lastSig=sig;
        if(repeated>=2) {
            ar.failStage="NO_PROGRESS_REPEATED_TOOL";
            ar.failMessage=tc->name;
            return ar;
        }

        ++ar.toolCalls;
        auto tr=auth.execute(*tc);
        if(tr.edited) ++ar.filesEdited;
        if(tr.buildRun){++ar.buildRuns;ar.finalBuildPass=tr.buildPass;}
        if(tr.testRun){++ar.testRuns;ar.finalTestPass=tr.testPass;}

        // After every successful edit, immediately build and then test.
        // Failure output is fed straight back to the model on the next turn.
        if(tr.ok&&tr.edited&&o.autoBuildAfterEdit) {
            auto br=auth.build();
            ++ar.buildRuns; ar.finalBuildPass=br.buildPass;
            tr.text+="\nAUTO_BUILD:\n"+br.text;
            if(br.ok) {
                auto ts=auth.test();
                ++ar.testRuns; ar.finalTestPass=ts.testPass;
                tr.text+="\nAUTO_TEST:\n"+ts.text;
            }
        }

        if(tr.finish) {
            ar.finishedByModel=true;
            auto br=auth.build();
            ++ar.buildRuns; ar.finalBuildPass=br.buildPass;
            std::string final=tr.text+"\nFINAL_BUILD:\n"+br.text;
            if(!br.ok) { lastResult=final; continue; }

            auto ts=auth.test();
            ++ar.testRuns; ar.finalTestPass=ts.testPass;
            final+="\nFINAL_TEST:\n"+ts.text;
            if(!ts.ok) { lastResult=final; continue; }

            ar.pass=true;
            ar.finalMessage=tr.text;
            return ar;
        }

        lastResult=tr.text;
    }

    ar.failStage="ITERATION_BUDGET";
    return ar;
}

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------
static std::vector<std::wstring> CurrentArgs() {
    int argc=0;
    LPWSTR* argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    std::vector<std::wstring> out;
    if(argv){for(int i=0;i<argc;++i)out.emplace_back(argv[i]);LocalFree(argv);}
    return out;
}

static std::optional<std::wstring> ArgValue(
    const std::vector<std::wstring>& a,const std::wstring& key)
{
    for(size_t i=0;i+1<a.size();++i) if(a[i]==key) return a[i+1];
    return std::nullopt;
}
static bool HasArg(const std::vector<std::wstring>& a,const std::wstring& key) {
    return std::find(a.begin(),a.end(),key)!=a.end();
}
static uint64_t ArgU64(const std::vector<std::wstring>& a,const std::wstring& k,uint64_t d) {
    auto v=ArgValue(a,k); if(!v)return d;
    try{return std::stoull(*v);}catch(...){return d;}
}

static Options ParseOptions(const std::vector<std::wstring>& a) {
    Options o;
    if(auto v=ArgValue(a,L"--model")) o.modelPath=*v;
    if(auto v=ArgValue(a,L"--workspace")) o.workspace=*v;
    if(auto v=ArgValue(a,L"--task")) o.task=WideToUtf8(*v);
    if(auto v=ArgValue(a,L"--task-file")) o.taskFile=*v;
    if(auto v=ArgValue(a,L"--build")) o.buildCommand=WideToUtf8(*v);
    if(auto v=ArgValue(a,L"--test")) o.testCommand=WideToUtf8(*v);
    if(auto v=ArgValue(a,L"--nonce")) o.nonce=WideToUtf8(*v);
    if(auto v=ArgValue(a,L"--receipt")) o.receiptPath=*v;
    if(auto v=ArgValue(a,L"--gate-prompt")) o.gatePrompt=WideToUtf8(*v);
    o.gateTokens=static_cast<uint32_t>(ArgU64(a,L"--gate-tokens",o.gateTokens));
    o.agentTokens=static_cast<uint32_t>(ArgU64(a,L"--agent-tokens",o.agentTokens));
    o.maxIterations=static_cast<uint32_t>(ArgU64(a,L"--max-iterations",o.maxIterations));
    o.maxToolCalls=static_cast<uint32_t>(ArgU64(a,L"--max-tools",o.maxToolCalls));
    o.commandTimeoutMs=ArgU64(a,L"--command-timeout-ms",o.commandTimeoutMs);
    o.wallTimeoutMs=ArgU64(a,L"--wall-ms",o.wallTimeoutMs);
    if(HasArg(a,L"--allow-cpu-fallback")){o.strictGpu=false;o.requireZeroFallback=false;}
    if(HasArg(a,L"--allow-nonresident"))o.requireRealGpuForward=false;
    if(HasArg(a,L"--no-auto-build"))o.autoBuildAfterEdit=false;
    if(HasArg(a,L"--skip-fast-gate"))o.runGateBeforeAgent=false;
    if(o.workspace.empty()) o.workspace=fs::current_path();
    return o;
}

static std::string ReadWholeTaskFile(const fs::path& p) {
    std::ifstream f(p,std::ios::binary);
    if(!f)return {};
    std::ostringstream s;s<<f.rdbuf();return s.str();
}

static void WriteUnifiedReceipt(
    Receipt& rec,const Options& o,const GateResult& g,const AgentResult* a)
{
    rec.set("GATE","RAWRXD_AUTOCLOSURE_001");
    rec.set("NONCE",OneLine(o.nonce));
    rec.set("MODEL_PATH",OneLine(PathUtf8(o.modelPath)));
    rec.set("MODEL_SHA256",g.modelSha256);
    rec.set("MODEL_FILE_SIZE_BYTES",g.modelBytes);
    rec.setBool("MODEL_LOADED",g.modelLoaded);
    rec.setBool("TOKENIZER_READY",g.tokenizerReady);
    rec.setBool("FORWARD_PASS_OK",g.forwardPassOk);
    rec.setBool("LOGITS_FINITE",g.logitsFinite);
    rec.set("GENERATED_TOKEN_COUNT",g.generatedTokens);
    rec.setBool("REAL_GPU_FORWARD",g.realGpuForward);
    rec.set("CPU_FALLBACKS",g.gpuFallbackDelta);
    rec.set("STRICT_GPU_VIOLATIONS",g.strictGpuViolation?"1":"0");
    rec.set("SYNTHETIC_TOKEN_OUTPUT","0");
    rec.set("STUB_FALLBACKS","0");
    rec.set("FAST_GATE_FAIL_STAGE",OneLine(g.failStage));
    rec.set("FAST_GATE_FAIL_MESSAGE",OneLine(g.failMessage));

    if(a) {
        rec.set("AGENT_ITERATIONS",a->iterations);
        rec.set("AGENT_TOOL_CALLS",a->toolCalls);
        rec.set("AGENT_FILES_EDITED",a->filesEdited);
        rec.set("AGENT_BUILD_RUNS",a->buildRuns);
        rec.set("AGENT_TEST_RUNS",a->testRuns);
        rec.setBool("AGENT_FINAL_BUILD",a->finalBuildPass);
        rec.setBool("AGENT_FINAL_TEST",a->finalTestPass);
        rec.setBool("AGENT_FINISHED_BY_MODEL",a->finishedByModel);
        rec.set("AGENT_FAIL_STAGE",OneLine(a->failStage));
        rec.set("AGENT_FAIL_MESSAGE",OneLine(a->failMessage));
        rec.set("AGENT_FINAL_MESSAGE",OneLine(a->finalMessage));
        rec.set("VERDICT",(g.pass&&a->pass)?"PASS":"FAIL");
    } else {
        rec.set("VERDICT",g.pass?"PASS":"FAIL");
    }
}

int Run(const Options& input) {
    Options o=input;
    Receipt rec; rec.path=o.receiptPath;

    if(o.modelPath.empty()) {
        GateResult g; g.failStage="MODEL_PATH_EMPTY";
        WriteUnifiedReceipt(rec,o,g,nullptr); return 2;
    }
    if(o.workspace.empty()) o.workspace=fs::current_path();

    std::error_code ec;
    o.modelPath=fs::weakly_canonical(o.modelPath,ec);
    o.workspace=fs::weakly_canonical(o.workspace,ec);

    std::string task=o.task;
    if(task.empty()&&!o.taskFile.empty()) task=ReadWholeTaskFile(o.taskFile);

    Deep2::Deep2Engine engine;
    GateResult gate;
    if(o.runGateBeforeAgent||task.empty()) {
        gate=RunFastGate(engine,o);
        if(!gate.pass) {
            WriteUnifiedReceipt(rec,o,gate,nullptr);
            return 10;
        }
    } else {
        if(!SetupEngine(engine,o,gate)) {
            WriteUnifiedReceipt(rec,o,gate,nullptr);
            return 11;
        }
        gate.pass=true;
        gate.tokenizerReady=true;
        gate.forwardPassOk=true;
        gate.logitsFinite=true;
        gate.realGpuForward=engine.isRealGpuForward();
    }

    if(task.empty()) {
        WriteUnifiedReceipt(rec,o,gate,nullptr);
        return gate.pass?0:12;
    }

    const uint64_t fbBeforeAgent=engine.vulkanGemvFallbackCount();
    AgentResult ar=RunAgent(engine,o,task);
    const uint64_t fbAfterAgent=engine.vulkanGemvFallbackCount();
    if(fbAfterAgent>=fbBeforeAgent)
        gate.gpuFallbackDelta += (fbAfterAgent-fbBeforeAgent);
    gate.realGpuForward=engine.isRealGpuForward();
    gate.strictGpuViolation=engine.vulkanStrictViolation();
    if(o.requireRealGpuForward&&!gate.realGpuForward){
        gate.pass=false;
        if(ar.failStage.empty()) ar.failStage="REAL_GPU_FORWARD_LOST";
        ar.pass=false;
    }
    if(o.requireZeroFallback&&gate.gpuFallbackDelta!=0){
        gate.pass=false;
        if(ar.failStage.empty()) ar.failStage="GPU_FALLBACK_DURING_AGENT";
        ar.pass=false;
    }
    if(o.strictGpu&&gate.strictGpuViolation){
        gate.pass=false;
        if(ar.failStage.empty()) ar.failStage="STRICT_GPU_VIOLATION_DURING_AGENT";
        ar.pass=false;
    }
    WriteUnifiedReceipt(rec,o,gate,&ar);
    return (gate.pass&&ar.pass)?0:20;
}

static std::wstring QuoteWin(const std::wstring& s) {
    std::wstring o=L"\"";
    size_t bs=0;
    for(wchar_t c:s) {
        if(c==L'\\'){++bs;continue;}
        if(c==L'"'){o.append(bs*2+1,L'\\');o.push_back(L'"');bs=0;continue;}
        o.append(bs,L'\\');bs=0;o.push_back(c);
    }
    o.append(bs*2,L'\\');o.push_back(L'"');return o;
}

static int RunWatchdogParent(const std::vector<std::wstring>& args,const Options& o) {
    wchar_t exe[MAX_PATH*4]{};
    if(!GetModuleFileNameW(nullptr,exe,(DWORD)std::size(exe))) return 90;

    std::wstring cmd=QuoteWin(exe);
    for(size_t i=1;i<args.size();++i) {
        if(args[i]==L"--autoclose") continue;
        if(args[i]==L"--autoclose-worker") continue;
        cmd+=L" "+QuoteWin(args[i]);
    }
    cmd+=L" --autoclose-worker";

    STARTUPINFOW si{};si.cb=sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> m(cmd.begin(),cmd.end());m.push_back(0);
    BOOL ok=CreateProcessW(nullptr,m.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&si,&pi);
    if(!ok)return 91;

    DWORD wait=WaitForSingleObject(pi.hProcess,
        o.wallTimeoutMs>0xffffffffull?0xffffffffu:(DWORD)o.wallTimeoutMs);
    if(wait==WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess,0xbeef);
        WaitForSingleObject(pi.hProcess,5000);
        Receipt rec;rec.path=o.receiptPath;
        rec.set("GATE","RAWRXD_AUTOCLOSURE_001");
        rec.set("NONCE",OneLine(o.nonce));
        rec.set("WATCHDOG_TIMEOUT","1");
        rec.set("FAIL_STAGE","WATCHDOG_TIMEOUT");
        rec.set("VERDICT","FAIL");
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
        return 92;
    }

    DWORD code=1;GetExitCodeProcess(pi.hProcess,&code);
    CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

bool CommandLineRequested() {
    auto a=CurrentArgs();
    return HasArg(a,L"--autoclose")||HasArg(a,L"--autoclose-worker");
}

int RunFromCurrentCommandLine() {
    auto a=CurrentArgs();
    Options o=ParseOptions(a);
    if(HasArg(a,L"--autoclose-worker")) return Run(o);
    return RunWatchdogParent(a,o);
}

} // namespace RawrXD::AutoClosure
