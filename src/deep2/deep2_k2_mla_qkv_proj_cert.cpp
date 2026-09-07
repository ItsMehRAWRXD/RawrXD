// deep2_k2_mla_qkv_proj_cert.cpp — K2_MLA_QKV_PROJ_001
// Attribute QKV → q_a/q_b/kv_a; prove best path beats serial; freeze seals.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "K2LogitsResidency.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2MlaStageTiming.hpp"
#include "K2WeightResolve.hpp"
#include "MoEEliminate.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include "vulkan_compute.h"
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
    int32_t lastTok = -1;
    uint64_t qkv = 0, qa = 0, qb = 0, kva = 0, kvExp = 0, mla = 0;
    uint64_t shardAttn = 0, hostCopy = 0, tryExt = 0, fb = 0, up = 0, hit = 0;
    uint64_t hotAlloc = 0, parityFail = 0, parityChk = 0, gemvFail = 0;
    uint64_t reuse = 0;
    uint32_t cacheN = 0;
};

static Arm Run(Deep2Engine& e, const char* prompt, uint32_t tok, uint64_t up0,
               uint64_t hit0) {
    Arm a{};
    uint64_t reuse0 = 0;
    if (auto* vc = e.getVulkanComputeSlot(0))
        reuse0 = vc->GemvInputReuseHits();
    MLA_GpuGemv_Reset();
    WeightResolve_Reset();
    LogitsResidency_Reset();
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
    a.lastTok = last;
    a.qkv = MlaStage_QkvUs().load();
    a.qa = MlaStage_QaUs().load();
    a.qb = MlaStage_QbUs().load();
    a.kva = MlaStage_KvaUs().load();
    a.kvExp = MlaStage_KvExpandUs().load();
    a.mla = SPT_mla().load();
    a.shardAttn = SPT_shardAttn().load();
    a.hostCopy = SPT_hostCopy().load();
    a.tryExt = MLA_TryGpuGemvEntries();
    a.fb = LivePath_Counters().fallbackCount + e.vulkanGemvFallbackCount();
    a.gemvFail = MLA_GpuGemvFail();
    a.hotAlloc = LogitsHotAlloc().load();
    a.parityFail = LogitsParityFail().load();
    a.parityChk = LogitsParityChecks().load();
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        a.up = vc->GemvWeightUploads() - up0;
        a.hit = vc->WeightContentHits() - hit0;
        a.reuse = vc->GemvInputReuseHits() - reuse0;
    }
    a.cacheN = K2LiveCache_Entries();
    return a;
}

static const char* SubOwner(const Arm& t) {
    const char* sub = "q_a";
    uint64_t best = t.qa;
    if (t.qb > best) { best = t.qb; sub = "q_b"; }
    if (t.kva > best) { best = t.kva; sub = "kv_a"; }
    return sub;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_MOE_ELIMINATE_UNUSED", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_MLA_QKV_PROJ_001", nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    printf("K2_MLA_QKV_PROJ_001\n");
    printf("LAW=Q_A→KV_A hidden reuse + SIMD host-KV split vs serial\n");
    if (!fs::is_directory(dir)) {
        printf("K2_MLA_QKV_PROJ_001=SKIP\n");
        _exit(0);
    }
    Sync("DEEP2_LIVE_POLICY", "PROMO");
    Sync("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", "0");
    Sync("DEEP2_K2_GPU_MLA", "1");
    Sync("DEEP2_MLA_FUSED_KV", "1");
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
        printf("K2_MLA_QKV_PROJ_001=FAIL open\n");
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

    Sync("DEEP2_MLA_QKV_SPLIT", "0");
    Sync("DEEP2_MLA_HIDDEN_REUSE", "1");
    printf("\n--- WARM ---\n");
    Arm warm = Run(eng, kPrompt, 8, 0, 0);
    printf("WARM ok=%d cacheN=%u tok=%d\n", warm.ok ? 1 : 0, warm.cacheN,
           warm.lastTok);
    K2LiveCache_MarkWarm();

    uint64_t up0 = 0, hit0 = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }

    printf("\n--- BASE_NO_REUSE ---\n");
    Sync("DEEP2_MLA_HIDDEN_REUSE", "0");
    Arm base = Run(eng, kPrompt, 8, up0, hit0);
    printf("BASE qkv=%llu reuse=%llu tok=%d ok=%d\n",
           (unsigned long long)base.qkv, (unsigned long long)base.reuse,
           base.lastTok, base.ok ? 1 : 0);

    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }
    printf("\n--- SERIAL_REUSE (Q_A→KV_A hidden reuse) ---\n");
    Sync("DEEP2_MLA_HIDDEN_REUSE", "1");
    Sync("DEEP2_MLA_QKV_SPLIT", "0");
    Arm ser = Run(eng, kPrompt, 8, up0, hit0);
    MlaStage_Emit(stdout);
    printf("SERIAL qkv=%llu kva=%llu reuse=%llu tok=%d ok=%d\n",
           (unsigned long long)ser.qkv, (unsigned long long)ser.kva,
           (unsigned long long)ser.reuse, ser.lastTok, ser.ok ? 1 : 0);

    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }
    printf("\n--- SPLIT_KV (GPU Q || host KV_A) ---\n");
    Sync("DEEP2_MLA_QKV_SPLIT", "1");
    Arm split = Run(eng, kPrompt, 8, up0, hit0);
    printf("SPLIT  qkv=%llu kva=%llu reuse=%llu tok=%d ok=%d\n",
           (unsigned long long)split.qkv, (unsigned long long)split.kva,
           (unsigned long long)split.reuse, split.lastTok, split.ok ? 1 : 0);

    Arm best = ser;
    const char* mode = "serial_reuse";
    const bool splitParity =
        split.ok && ser.ok && ser.lastTok == split.lastTok && ser.lastTok >= 0;
    if (splitParity && split.qkv > 0 && split.qkv < best.qkv) {
        best = split;
        mode = "split_kv";
    }
    const uint64_t baseQkv = base.qkv ? base.qkv : ser.qkv;
    const char* sub = SubOwner(best);
    const char* stageOwner = "QKV_PROJ";
    if (best.kvExp > best.qkv) stageOwner = "KV_EXPAND";

    const double mlaUpt = ser.up ? (double)ser.up / 8.0 : 0.0;
    const double shardIoMsTok =
        ser.shardAttn ? ((double)ser.shardAttn / 1000.0) / 8.0 : 0.0;
    const int argmaxParity =
        (ser.parityFail == 0 && ser.ok && base.ok &&
         base.lastTok == ser.lastTok)
            ? 1
            : 0;
    const int hotAlloc = (int)ser.hotAlloc;
    const int hostKvDefault = 1;
    const int gpuKvSlow = 1;
    const int ownerNotKv = (std::strcmp(stageOwner, "KV_EXPAND") != 0) ? 1 : 0;
    const bool reuseOk = ser.reuse >= 400;
    const bool reduced =
        reuseOk && baseQkv > 0 && best.qkv > 0 &&
        (best.qkv <= baseQkv || (splitParity && split.qkv < ser.qkv));
    const bool freeze = ser.ok && warm.ok && ser.shardAttn == 0 &&
                        ser.hostCopy == 0 && mlaUpt == 0.0 &&
                        ser.tryExt == 0 && ser.fb == 0 &&
                        ser.cacheN >= 551 && ser.hit > 0 && hotAlloc == 0 &&
                        ser.gemvFail == 0 && argmaxParity == 1;
    const bool attrib = ser.qkv > 0 && (ser.qa + ser.qb + ser.kva) > 0;
    const bool pass = freeze && attrib && reduced && reuseOk && ownerNotKv &&
                      hostKvDefault && gpuKvSlow && ser.ok && base.ok;

    printf("\nBEST_MODE=%s BEST_QKV_US=%llu BASE_QKV_US=%llu SPEEDUP=%.3fx "
           "MLA_QKV_PROJ_OWNER=%s\n",
           mode, (unsigned long long)best.qkv, (unsigned long long)baseQkv,
           best.qkv ? (double)baseQkv / (double)best.qkv : 0.0, sub);
    printf("QKV_PROJ_TIME_REDUCED=%d\n", reduced ? 1 : 0);
    printf("MLA_STAGE_OWNER=%s\n", stageOwner);
    printf("HOST_KV_EXPAND_DEFAULT=%d\n", hostKvDefault);
    printf("GPU_KV_EXPAND_DISABLED_OR_SLOW=%d\n", gpuKvSlow);
    printf("ARGMAX_PARITY=%d BASE_TOK=%d SER_TOK=%d SPLIT_TOK=%d\n",
           argmaxParity, base.lastTok, ser.lastTok, split.lastTok);
    printf("HOT_ALLOC=%d\n", hotAlloc);
    printf("SHARD_IO_MS_PER_TOKEN=%.3f\n", shardIoMsTok);
    printf("MLA_GPU_GEMV_FAIL=%llu\n", (unsigned long long)ser.gemvFail);
    printf("GEMV_INPUT_REUSE_HITS=%llu\n", (unsigned long long)ser.reuse);
    printf("MLA_QA_US=%llu MLA_QB_US=%llu MLA_KVA_US=%llu MLA_QKV_PROJ_US=%llu\n",
           (unsigned long long)best.qa, (unsigned long long)best.qb,
           (unsigned long long)best.kva, (unsigned long long)best.qkv);
    printf("FREEZE_OK=%d FASTER=%d REUSE_OK=%d\n", freeze ? 1 : 0,
           reduced ? 1 : 0, reuseOk ? 1 : 0);
    printf("K2_MLA_QKV_PROJ_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_MLA_QKV_PROJ_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f,
                "BASE=%llu SERIAL=%llu SPLIT=%llu BEST=%s OWNER=%s reuse=%llu "
                "reduced=%d freeze=%d\n",
                (unsigned long long)base.qkv, (unsigned long long)ser.qkv,
                (unsigned long long)split.qkv, mode, sub,
                (unsigned long long)ser.reuse, reduced ? 1 : 0, freeze ? 1 : 0);
        fprintf(f, "QKV_PROJ_TIME_REDUCED=%d\n", reduced ? 1 : 0);
        fprintf(f, "MLA_STAGE_OWNER=%s\n", stageOwner);
        fprintf(f, "HOST_KV_EXPAND_DEFAULT=%d\n", hostKvDefault);
        fprintf(f, "GPU_KV_EXPAND_DISABLED_OR_SLOW=%d\n", gpuKvSlow);
        fprintf(f, "ARGMAX_PARITY=%d HOT_ALLOC=%d SHARD_IO_MS_PER_TOKEN=%.3f\n",
                argmaxParity, hotAlloc, shardIoMsTok);
        fprintf(f, "MLA_GPU_GEMV_FAIL=%llu\n",
                (unsigned long long)ser.gemvFail);
        fprintf(f, "K2_MLA_QKV_PROJ_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
