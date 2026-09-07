// deep2_k2_gpu_mla_full_depth_cert.cpp — K2_GPU_MLA_FULL_DEPTH_001
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
    return a; // leak eng
}
int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1","1");
    _putenv_s("DEEP2_WEIGHT_MODE","BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB","6144");
    _putenv_s("DEEP2_WEIGHT_SLOTS","8");
#endif
    const char* dir=std::getenv("DEEP2_K2_SHARD_DIR");
    if(!dir||!dir[0]) dir="F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_FULL_DEPTH_001",nullptr);
    uint32_t nTok=4, depth=61;
    if(const char* t=std::getenv("DEEP2_EFF_TOKENS")) nTok=(uint32_t)atoi(t);
    if(const char* d=std::getenv("DEEP2_EFF_LAYER_DEPTH")) depth=(uint32_t)atoi(d);
    if(nTok<2) nTok=2;
    const uint64_t unique=6ull*depth;
    printf("K2_GPU_MLA_FULL_DEPTH_001\nMODEL=%s DEPTH=%u TOKENS=%u\n",dir,depth,nTok);
    printf("PIN=layer-tensor-key POLICY=OFF BUDGET_MIB=6144\n");
    if(!fs::is_directory(dir)){ printf("K2_GPU_MLA_FULL_DEPTH_001=SKIP\n"); return 0; }
    static const char* kPrompt="Write one short paragraph on local decode tok/s.";
    printf("\n--- t1 parity ---\n");
    Arm c1=Run(dir,kPrompt,1,1,false);
    Arm g1=Run(dir,kPrompt,1,1,true);
    const bool parity1=c1.ok&&g1.ok&&c1.tok==g1.tok&&c1.text==g1.text;
    const bool ops1=g1.mlaOk==6&&g1.mlaFail==0;
    printf("CPU_TOK=%d GPU_TOK=%d MLA=%llu PARITY=%d\n",(int)c1.tok,(int)g1.tok,(unsigned long long)g1.mlaOk,parity1?1:0);
    printf("\n--- full-depth rebench ---\n");
    Arm A=Run(dir,kPrompt,depth,nTok,false);
    Arm B=Run(dir,kPrompt,depth,nTok,true);
    printf("A_CPU tps=%.3f wall=%.0f tok=%d ok=%d\n",A.tps,A.wallMs,(int)A.tok,A.ok?1:0);
    printf("B_GPU tps=%.3f wall=%.0f tok=%d mla=%llu fail=%llu hits=%llu uploads=%llu ok=%d\n",
           B.tps,B.wallMs,(int)B.tok,(unsigned long long)B.mlaOk,(unsigned long long)B.mlaFail,
           (unsigned long long)B.hits,(unsigned long long)B.uploads,B.ok?1:0);
    const bool parity=A.ok&&B.ok&&A.tok==B.tok&&A.text==B.text;
    const bool used=B.mlaOk>0&&B.mlaFail==0;
    const bool reused=B.hits+2>=unique*(nTok-1);
    const bool floor=B.tps+1e-12>=A.tps*0.90;
    const bool promote=parity1&&parity&&used&&B.tps+1e-12>=A.tps*0.97;
    const bool pass=parity1&&ops1&&parity&&used&&reused&&floor&&promote;
    printf("OUTPUT_PARITY=%d MLA_USED=%d REUSED=%d FLOOR90=%d\n",parity?1:0,used?1:0,reused?1:0,floor?1:0);
    printf("POLICY_DECISION=%s TPS_DELTA=%+.3f\n",promote?"PROMOTE_GPU_MLA":"HOLD_OPT_IN",B.tps-A.tps);
    printf("K2_GPU_MLA_FULL_DEPTH_001=%s\n",pass?"PASS":"FAIL");
    FILE* f=fopen("G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_FULL_DEPTH_001\\GATE_STATUS.txt","w");
    if(f){fprintf(f,"A=%.3f B=%.3f hits=%llu uploads=%llu parity=%d promote=%d\n",A.tps,B.tps,(unsigned long long)B.hits,(unsigned long long)B.uploads,parity,promote);fprintf(f,"POLICY_DECISION=%s\n",promote?"PROMOTE_GPU_MLA":"HOLD_OPT_IN");fprintf(f,"K2_GPU_MLA_FULL_DEPTH_001=%s\n",pass?"PASS":"FAIL");fclose(f);}
    fflush(stdout); _exit(pass?0:2);
}
