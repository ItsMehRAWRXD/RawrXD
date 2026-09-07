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
    bool ok=false; double tps=0, wallMs=0, work=0;
    int32_t tok=-1; std::string text;
    uint64_t mlaOk=0, mlaFail=0, hits=0, uploads=0;
};
static void Env(const char* dir, uint32_t depth, bool gpuMla) {
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_K2_SHARD_DIR", dir);
    _putenv_s("DEEP2_K2_SHARD_DIR", dir);
    _putenv_s("DEEP2_LIVE_POLICY", "OFF");
    _putenv_s("DEEP2_LIVE_MECH", "none");
    _putenv_s("DEEP2_GEN_ALG", "standard");
    _putenv_s("DEEP2_MLA_SERIAL", "1");
    _putenv_s("DEEP2_K2_GPU_STREAM_COPY", gpuMla ? "1" : "0");
    _putenv_s("DEEP2_K2_GPU_MLA", gpuMla ? "1" : "0");
    _putenv_s("DEEP2_WEIGHT_PIN", gpuMla ? "1" : "0");
    _putenv_s("DEEP2_TRAMP_FAST_IO", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
#endif
}
static Arm Timed(Deep2Engine& eng, const char* prompt, uint32_t depth, uint32_t tokens) {
    Arm a{};
    MLA_GpuGemv_Reset(); K2GpuStreamCopy_Reset(); StreamTransfer_Reset(); GpuTransfer_Reset();
    K2NativeStreamGate::Config kc;
    kc.prompt=prompt; kc.streamTokens=tokens; kc.layerDepth=depth;
    kc.enableMlaComplete=true; kc.budgetBytes=512ull<<20;
    auto t0=std::chrono::steady_clock::now();
    auto r=eng.runK2NativeStreamPartial(kc);
    a.wallMs=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-t0).count();
    a.ok=r.ok; a.tok=r.generatedTokenId; a.text=r.generatedText;
    a.tps=(r.ok&&tokens&&a.wallMs>0)?(1000.0*tokens/a.wallMs):0.0;
    a.work=a.tps*a.wallMs/1000.0;
    a.mlaOk=MLA_GpuGemvOps(); a.mlaFail=MLA_GpuGemvFail();
    if (auto* vc=eng.getVulkanComputeSlot(0)) { a.hits=vc->WeightContentHits(); a.uploads=vc->GemvWeightUploads(); }
    return a;
}
static Deep2Engine* Open(const char* dir) {
    Deep2Engine* eng = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim=7168; cfg.numLayers=61; cfg.numHeads=64; cfg.numKVHeads=1;
    cfg.vocabSize=163840; cfg.useMLA=true; cfg.maxSeqLen=128; cfg.useKVCache=true;
    cfg.useThreadPool=true; cfg.numThreads=8;
    if (!eng->initialize(cfg) || !eng->openK2ShardDirectory(dir)) return nullptr;
    return eng;
}
int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1","1");
    _putenv_s("DEEP2_WEIGHT_MODE","BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB","6144");
#endif
    const char* dir=std::getenv("DEEP2_K2_SHARD_DIR");
    if(!dir||!dir[0]) dir="F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_FULL_DEPTH_001",nullptr);
    uint32_t nTok=2, depth=61;
    if(const char* t=std::getenv("DEEP2_EFF_TOKENS")) nTok=(uint32_t)atoi(t);
    if(const char* d=std::getenv("DEEP2_EFF_LAYER_DEPTH")) depth=(uint32_t)atoi(d);
    if(nTok<1) nTok=1;
    printf("K2_GPU_MLA_FULL_DEPTH_001\nMODEL=%s DEPTH=%u TOKENS=%u\n",dir,depth,nTok);
    printf("PIN=Q4-resident POLICY=OFF NVME=SHARD_IO work=tps*wall/1000\n");
    if(!fs::is_directory(dir)){ printf("SKIP\n"); return 0; }
    static const char* kPrompt="Write one short paragraph on local decode tok/s.";

    printf("\n--- t1 parity ---\n");
    Env(dir,1,false); Deep2Engine* eC=Open(dir); Arm c1=Timed(*eC,kPrompt,1,1);
    Env(dir,1,true);  Deep2Engine* eG=Open(dir); Arm g1=Timed(*eG,kPrompt,1,1);
    const bool parity1=c1.ok&&g1.ok&&c1.tok==g1.tok&&c1.text==g1.text;
    const bool ops1=g1.mlaOk>=3&&g1.mlaFail==0;
    printf("CPU_TOK=%d GPU_TOK=%d MLA=%llu PARITY=%d work=%.3f\n",
           (int)c1.tok,(int)g1.tok,(unsigned long long)g1.mlaOk,parity1?1:0,g1.work);

    printf("\n--- full-depth: A CPU | warm+B GPU same Vk device ---\n");
    Env(dir,depth,false); Deep2Engine* eA=Open(dir);
    Arm A=Timed(*eA,kPrompt,depth,nTok);
    Env(dir,depth,true); Deep2Engine* eB=Open(dir);
    printf("warm pin (untimed 1 tok)...\n");
    (void)Timed(*eB,kPrompt,depth,1); // fills pin residents on eB
    uint64_t warmHits=0, warmUp=0;
    if (auto* vc=eB->getVulkanComputeSlot(0)) { warmHits=vc->WeightContentHits(); warmUp=vc->GemvWeightUploads(); }
    printf("warm uploads=%llu hits=%llu\n",(unsigned long long)warmUp,(unsigned long long)warmHits);
    Arm B=Timed(*eB,kPrompt,depth,nTok); // timed with hot pins
    printf("A_CPU tps=%.3f wall=%.0f work=%.3f tok=%d ok=%d\n",A.tps,A.wallMs,A.work,(int)A.tok,A.ok?1:0);
    printf("B_GPU tps=%.3f wall=%.0f work=%.3f tok=%d mla=%llu fail=%llu hits=%llu uploads=%llu ok=%d\n",
           B.tps,B.wallMs,B.work,(int)B.tok,(unsigned long long)B.mlaOk,(unsigned long long)B.mlaFail,
           (unsigned long long)B.hits,(unsigned long long)B.uploads,B.ok?1:0);
    const bool parity=A.ok&&B.ok&&A.tok==B.tok&&A.text==B.text;
    const bool used=B.mlaOk>0&&B.mlaFail==0;
    const bool floor=B.tps+1e-12>=A.tps*0.90;
    const bool promote=parity1&&parity&&used&&B.tps+1e-12>=A.tps*0.97;
    const bool pass=parity1&&ops1&&parity&&used&&floor&&promote;
    printf("OUTPUT_PARITY=%d MLA_USED=%d FLOOR90=%d\n",parity?1:0,used?1:0,floor?1:0);
    printf("POLICY_DECISION=%s TPS_DELTA=%+.3f\n",promote?"PROMOTE_GPU_MLA":"HOLD_OPT_IN",B.tps-A.tps);
    printf("K2_GPU_MLA_FULL_DEPTH_001=%s\n",pass?"PASS":"FAIL");
    FILE* f=fopen("G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_FULL_DEPTH_001\\GATE_STATUS.txt","w");
    if(f){fprintf(f,"A=%.3f B=%.3f workA=%.3f workB=%.3f hits=%llu uploads=%llu parity=%d promote=%d\n",A.tps,B.tps,A.work,B.work,(unsigned long long)B.hits,(unsigned long long)B.uploads,parity,promote);fprintf(f,"POLICY_DECISION=%s\n",promote?"PROMOTE_GPU_MLA":"HOLD_OPT_IN");fprintf(f,"K2_GPU_MLA_FULL_DEPTH_001=%s\n",pass?"PASS":"FAIL");fprintf(f,"NOTE=Q4_K pin+SHARD_IO; work=tps*wall/1000; warm then timed B.\n");fclose(f);}
    fflush(stdout); _exit(pass?0:2);
}