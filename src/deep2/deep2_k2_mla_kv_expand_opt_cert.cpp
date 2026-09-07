// deep2_k2_mla_kv_expand_opt_cert.cpp — K2_MLA_KV_EXPAND_OPT_001
// Prove host fused KV expand beats GPU dual MLA_Gemv; seals held on default path.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2MlaStageTiming.hpp"
#include "K2WeightResolve.hpp"
#include "MoEEliminate.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

struct Arm {
    bool ok = false;
    uint64_t kvExp = 0, mlaUs = 0, up = 0, hit = 0, tryExt = 0, fb = 0;
    uint64_t shardAttn = 0, hostCopy = 0;
    uint32_t cacheN = 0;
};

static Arm Run(Deep2Engine& e, const char* prompt, uint32_t tok, uint64_t up0,
               uint64_t hit0) {
    Arm a{};
    MLA_GpuGemv_Reset();
    WeightResolve_Reset();
    MlaStage_Reset();
    StreamPathTiming_Reset();
    StreamTransfer_Reset();
    GenerationOptions opts{};
    opts.maxTokens = tok;
    opts.temperature = 0.0f;
    opts.topK = 1;
    std::string text;
    int32_t last = -1;
    auto r = e.generateStream(prompt, opts,
                              [&](int32_t id, const std::string& t) -> bool {
                                  last = id;
                                  text += t;
                                  return true;
                              });
    a.ok = r.completed && !text.empty() && last >= 0;
    a.kvExp = MlaStage_KvExpandUs().load();
    a.mlaUs = SPT_mla().load();
    a.shardAttn = SPT_shardAttn().load();
    a.hostCopy = SPT_hostCopy().load();
    a.tryExt = MLA_TryGpuGemvEntries();
    a.fb = LivePath_Counters().fallbackCount + e.vulkanGemvFallbackCount();
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        a.up = vc->GemvWeightUploads() - up0;
        a.hit = vc->WeightContentHits() - hit0;
    }
    a.cacheN = K2LiveCache_Entries();
    return a;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_MOE_ELIMINATE_UNUSED", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_MLA_KV_EXPAND_OPT_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    printf("K2_MLA_KV_EXPAND_OPT_001\n");
    printf("LAW=host fused KV expand default; beats GPU dual MLA_Gemv pair\n");
    if (!fs::is_directory(dir)) {
        printf("K2_MLA_KV_EXPAND_OPT_001=SKIP\n");
        _exit(0);
    }
    Sync("DEEP2_LIVE_POLICY", "PROMO");
    Sync("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", "0");
    Sync("DEEP2_K2_GPU_MLA", "1");
    Sync("DEEP2_WEIGHT_PIN", "1");
    Sync("DEEP2_WEIGHT_PREFETCH", "0");
    Sync("DEEP2_LIVE_MECH", "trampoline,cyclone,elastic");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    Sync("RAWRXD_GPU_FWD", "0");
    Sync("RAWRXD_K2_LAYERS", "61");
    Sync("DEEP2_WEIGHT_SLOTS", "16");
    SetEnvironmentVariableA("DEEP2_WEIGHT_BUDGET_MIB", nullptr);
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "");

    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168;
    cfg.numLayers = 61;
    cfg.numHeads = 64;
    cfg.numKVHeads = 1;
    cfg.vocabSize = 163840;
    cfg.useMLA = true;
    cfg.maxSeqLen = 256;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_MLA_KV_EXPAND_OPT_001=FAIL open\n");
        _exit(2);
    }
    ElasticDynamicProbe p{};
    ElasticBudget_ProbeHost(p);
    p.layers = 61;
    auto caps = ElasticBudget_Derive(p);
    eng.enableElasticResidency(true);
    eng.refreshElasticDynamicBudget();
    if (!eng.isVulkanInitialized()) eng.enableVulkan(true);
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        vc->SetPinResidentBudget(caps.maxHotBytes);
        vc->ReleaseWeightWindow();
        vc->ClearPinnedGemvWeights();
        K2GpuStreamCopy_Bind(vc);
    }
    MoEEliminate_Reset();
    K2LiveCache_Reset((std::max)(caps.maxHotBytes, 12288ull << 20));
    static const char* kPrompt =
        "Write one short sentence about local decode throughput.";
    K2LivePolicy_ClearSticky();

    Sync("DEEP2_MLA_FUSED_KV", "1");
    printf("\n--- WARM ---\n");
    Arm warm = Run(eng, kPrompt, 8, 0, 0);
    printf("WARM ok=%d cacheN=%u\n", warm.ok ? 1 : 0, warm.cacheN);
    K2LiveCache_MarkWarm();

    uint64_t up0 = 0, hit0 = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }

    printf("\n--- HOST_FUSED (default authority) ---\n");
    Sync("DEEP2_MLA_FUSED_KV", "1");
    Arm host = Run(eng, kPrompt, 8, up0, hit0);
    printf("HOST kvExp=%llu mla=%llu ok=%d up=%llu hit=%llu\n",
           (unsigned long long)host.kvExp, (unsigned long long)host.mlaUs,
           host.ok ? 1 : 0, (unsigned long long)host.up,
           (unsigned long long)host.hit);

    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }
    printf("\n--- GPU_DUAL (DEEP2_MLA_FUSED_KV=0) ---\n");
    Sync("DEEP2_MLA_FUSED_KV", "0");
    Arm gpu = Run(eng, kPrompt, 8, up0, hit0);
    printf("GPU  kvExp=%llu mla=%llu ok=%d up=%llu hit=%llu\n",
           (unsigned long long)gpu.kvExp, (unsigned long long)gpu.mlaUs,
           gpu.ok ? 1 : 0, (unsigned long long)gpu.up,
           (unsigned long long)gpu.hit);

    const bool freeze = host.ok && warm.ok && host.shardAttn == 0 &&
                        host.hostCopy == 0 && host.tryExt == 0 &&
                        host.fb == 0 && host.cacheN >= 551;
    const bool faster = (gpu.kvExp > 0) && (host.kvExp > 0) &&
                        (host.kvExp < gpu.kvExp);
    const bool pass = freeze && faster;

    printf("\nHOST_KV_EXPAND_US=%llu GPU_KV_EXPAND_US=%llu SPEEDUP=%.3fx\n",
           (unsigned long long)host.kvExp, (unsigned long long)gpu.kvExp,
           host.kvExp ? (double)gpu.kvExp / (double)host.kvExp : 0.0);
    printf("FREEZE_OK=%d FASTER=%d\n", freeze ? 1 : 0, faster ? 1 : 0);
    printf("K2_MLA_KV_EXPAND_OPT_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_MLA_KV_EXPAND_OPT_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "HOST=%llu GPU=%llu freeze=%d faster=%d\n",
                (unsigned long long)host.kvExp, (unsigned long long)gpu.kvExp,
                freeze ? 1 : 0, faster ? 1 : 0);
        fprintf(f, "K2_MLA_KV_EXPAND_OPT_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
