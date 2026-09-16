#include "deep2/Deep2Engine.h"
#include "deep2/Deep2Speculative.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static LONG CALLBACK Deep2InPageProbe(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    const EXCEPTION_RECORD* r = ep->ExceptionRecord;

    if (r->ExceptionCode != 0xC0000006u)
        return EXCEPTION_CONTINUE_SEARCH;

    std::fprintf(stderr,
        "\n"
        "DEEP2_INPAGE_FAULT=1\n"
        "EXCEPTION_CODE=0x%08lX\n"
        "EXCEPTION_ADDRESS=%p\n"
        "EXCEPTION_PARAMS=%lu\n",
        r->ExceptionCode,
        r->ExceptionAddress,
        r->NumberParameters);

    for (ULONG i = 0; i < r->NumberParameters; ++i) {
        std::fprintf(stderr,
            "EXCEPTION_INFO_%lu=0x%llX\n",
            i,
            static_cast<unsigned long long>(
                r->ExceptionInformation[i]));
    }

    if (r->NumberParameters >= 3) {
        std::fprintf(stderr,
            "INPAGE_OPERATION=0x%llX\n"
            "INPAGE_ADDRESS=0x%llX\n"
            "INPAGE_UNDERLYING_STATUS=0x%08llX\n",
            static_cast<unsigned long long>(
                r->ExceptionInformation[0]),
            static_cast<unsigned long long>(
                r->ExceptionInformation[1]),
            static_cast<unsigned long long>(
                r->ExceptionInformation[2] & 0xffffffffull));
    }

    std::fflush(stderr);
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif // _WIN32

using namespace Deep2;

static bool setup(Deep2Engine& e,const char* model,bool spec) {
    std::fprintf(stderr,"SPEC_SETUP_ENTER spec=%d\n",(int)spec); fflush(stderr);
    EngineConfig c{};
    c.maxSeqLen=4096;
    std::fprintf(stderr,"SPEC_INIT_BEGIN\n"); fflush(stderr);
    if(!e.initialize(c)) { std::fprintf(stderr,"SPEC_INIT_FAIL\n"); fflush(stderr); return false; }
    std::fprintf(stderr,"SPEC_INIT_OK\n"); fflush(stderr);
    std::fprintf(stderr,"SPEC_LOAD_BEGIN\n"); fflush(stderr);
    bool loadOk=e.loadModel(model);
    std::fprintf(stderr,"SPEC_LOAD_END ok=%d\n",(int)loadOk); fflush(stderr);
    if(!loadOk) return false;
    const auto& g=e.getConfig();
    if(g.numLayers!=64||g.hiddenDim!=5120||
       g.numHeads!=40||g.numKVHeads!=8)
        return false;
    e.setVulkanStrictNoCpuFallback(true);
    std::fprintf(stderr,"SPEC_VK_BEGIN spec=%d\n",(int)spec); fflush(stderr);
    e.enableVulkan(true);
    std::fprintf(stderr,"SPEC_VK_END initialized=%d devices=%u\n",
        (int)e.isVulkanInitialized(),
        (unsigned)e.vulkanDeviceCount()); fflush(stderr);
    if(!e.isVulkanInitialized()||e.vulkanDeviceCount()<2) return false;
    std::fprintf(stderr,"SPEC_CONFIG_BEGIN\n"); fflush(stderr);
    GenerationOptions o{};
    o.temperature=0.0f;o.topK=1;o.topP=1.0f;o.seed=1;
    e.configureGeneration(o);
    e.enableVerifiedSpeculation(spec,4);
    std::fprintf(stderr,"SPEC_CONFIG_END\n"); fflush(stderr);
    std::fprintf(stderr,"SPEC_SETUP_EXIT\n"); fflush(stderr);
    return true;
}

static std::vector<int> run(
    Deep2Engine& e,const std::string& prompt,size_t n,InferenceStats& s)
{
    std::fprintf(stderr,"RUN_TOKENIZE_BEGIN n=%zu\n",n); fflush(stderr);
    auto p=e.tokenize(prompt);
    std::fprintf(stderr,"RUN_TOKENIZE_OK tokens=%zu\n",p.size()); fflush(stderr);
    std::vector<int> out(n);
    std::fprintf(stderr,"RUN_GENERATE_BEGIN prompt=%zu out=%zu\n",p.size(),out.size()); fflush(stderr);
    const size_t got=e.generate(
        p.data(),p.size(),out.data(),out.size(),&s);
    std::fprintf(stderr,"RUN_GENERATE_END got=%zu\n",got); fflush(stderr);
    out.resize(got);
    return out;
}

int main(int argc,char** argv) {
    if(argc<2) {
        std::fprintf(stderr,"usage: qwen32_85tps_gate model.gguf [--only N]\n");
        return 2;
    }
    const char* model=argv[1];
    const std::string prompt=
        "Implement a high performance C++ lock free queue and explain "
        "the memory ordering guarantees in detail. ";

    int onlyNtok = -1;
    if(argc>=4 && std::strcmp(argv[2],"--only")==0) {
        onlyNtok = std::atoi(argv[3]);
        std::fprintf(stderr,"GATE_ONLY_MODE ntok=%d\n",onlyNtok); fflush(stderr);
    }

    const int thresholds[] = {1,2,3,4,5,6,7,8,12,16};
    const int numThresholds = (int)(sizeof(thresholds)/sizeof(thresholds[0]));

    for(int ti=0; ti<numThresholds; ++ti) {
        const int ntok = thresholds[ti];
        if(onlyNtok>0 && ntok!=onlyNtok) continue;
        std::fprintf(stderr,"\n=== THRESHOLD ntok=%d ===\n",ntok); fflush(stderr);
        Deep2Engine e;
        if(!setup(e,model,true)) {
            std::fprintf(stderr,"THRESHOLD_SETUP_FAIL ntok=%d\n",ntok); fflush(stderr);
            return 20;
        }
        std::fprintf(stderr,"THRESHOLD_SETUP_OK ntok=%d\n",ntok); fflush(stderr);
        InferenceStats s{};
        std::fprintf(stderr,"THRESHOLD_GEN_BEGIN ntok=%d\n",ntok); fflush(stderr);
        auto x=run(e,prompt,(size_t)ntok,s);
        std::fprintf(stderr,"THRESHOLD_GEN_END ntok=%d got=%zu\n",ntok,x.size()); fflush(stderr);
        if(x.size()==(size_t)ntok) {
            std::fprintf(stderr,"THRESHOLD_RESULT ntok=%d PASS\n",ntok); fflush(stderr);
        } else {
            std::fprintf(stderr,"THRESHOLD_RESULT ntok=%d FAIL got=%zu\n",ntok,x.size()); fflush(stderr);
            std::fprintf(stderr,"FIRST_FAILING_THRESHOLD=%d\n",ntok); fflush(stderr);
            break;
        }
    }

    std::fprintf(stderr,"\n=== THRESHOLD LADDER COMPLETE ===\n"); fflush(stderr);
    return 0;
}
