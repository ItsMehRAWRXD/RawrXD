#include "Deep2Engine.h"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "StreamTransferCounters.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;
struct Arm {
    bool ok=false; double tps=0, wallMs=0; int32_t tok=-1; std::string text;
    uint64_t mlaOk=0, mlaFail=0, hits=0, uploads=0;
};
static Arm Run(const char* dir, const char* prompt, uint32_t depth, uint32_t tokens, bool gpuMla) {
    Arm a{};
#ifdef _WIN32
    _putenv_s("DEEP2_LIVE_POLICY", "OFF");
    _putenv_s("DEEP2_MLA_SERIAL", "1");
    _putenv_s("DEEP2_K2_GPU_STREAM_COPY", gpuMla ? "1" : "0");
    _putenv_s("DEEP2_K2_GPU_MLA", gpuMla ? "1" : "0");
    _putenv_s("DEEP2_WEIGHT_PIN", gpuMla ? "1" : "0");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
#endif
    MLA_GpuGemv_Reset(); K2GpuStreamCopy_Reset(); StreamTransfer_Reset(); GpuTransfer_Reset();
    Deep2Engine* eng = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim=7168; cfg.numLayers=61; cfg.numHeads=64; cfg.numKVHeads=1;
    cfg.vocabSize=163840; cfg.useMLA=true; cfg.maxSeqLen=128; cfg.useKVCache=true;
    cfg.useThreadPool=true; cfg.numThreads=8;
    if (!eng->initialize(cfg) || !eng->openK2ShardDirectory(dir)) return a;
    K2NativeStreamGate::Config kc;
    kc.prompt=prompt; kc.streamTokens=tokens; kc.layerDepth=depth;
    kc.enableMlaComplete=true; kc.budgetBytes=512ull<<20;
    auto t0=std::chrono::steady_clock::now();
    auto r=eng->runK2NativeStreamPartial(kc);
    a.wallMs=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-t0).count();
    a.ok=r.ok; a.tok=r.generatedTokenId; a.text=r.generatedText;
    a.tps=(r.ok&&tokens&&a.wallMs>0)?(1000.0*tokens/a.wallMs):0.0;
    a.mlaOk=MLA_GpuGemvOps(); a.mlaFail=MLA_GpuGemvFail();
    if (auto* vc=eng->getVulkanComputeSlot(0)) { a.hits=vc->WeightContentHits(); a.uploads=vc->GemvWeightUploads(); }
    return a;
}
int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1","1");
    _putenv_s("DEEP2_WEIGHT_MODE","BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB","6144");
#endif
    const char* dir=std::getenv("DEEP2_K2_SHARD_DIR");
    if(!dir||!dir[0]) dir="F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    static const char* kPrompt="Write one short paragraph on local decode tok/s.";
    printf("ISOLATE d61 t1 (no reuse)\n");
    Arm A=Run(dir,kPrompt,61,1,false);
    Arm B=Run(dir,kPrompt,61,1,true);
    printf("A tok=%d tps=%.3f wall=%.0f work=%.3f\n",(int)A.tok,A.tps,A.wallMs,A.tps*A.wallMs/1000.0);
    printf("B tok=%d tps=%.3f wall=%.0f work=%.3f mla=%llu hits=%llu uploads=%llu\n",
           (int)B.tok,B.tps,B.wallMs,B.tps*B.wallMs/1000.0,
           (unsigned long long)B.mlaOk,(unsigned long long)B.hits,(unsigned long long)B.uploads);
    printf("PARITY=%d\n",(A.ok&&B.ok&&A.tok==B.tok&&A.text==B.text)?1:0);
    _exit((A.ok&&B.ok&&A.tok==B.tok)?0:2);
}
