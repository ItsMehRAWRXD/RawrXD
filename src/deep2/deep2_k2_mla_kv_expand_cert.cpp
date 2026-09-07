// deep2_k2_mla_kv_expand_cert.cpp — K2_MLA_KV_EXPAND_001
// Attribute MLA_COMPUTE into QKV / KV_EXPAND / ATTN / O_PROJ; freeze seals.
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
    uint32_t tokens = 0;
    uint64_t mlaUs = 0, logitsUs = 0, shardAttnUs = 0, hostCopyUs = 0;
    uint64_t qkv = 0, kvExp = 0, attn = 0, oProj = 0;
    uint64_t up = 0, hit = 0, tryExt = 0, fb = 0;
    uint64_t attnShard = 0, q6Hit = 0, hotAlloc = 0;
    uint32_t cacheEntries = 0;
};

static Arm Run(Deep2Engine& e, const char* prompt, uint32_t tok, uint64_t up0,
               uint64_t hit0) {
    Arm a{};
    a.tokens = tok;
    MLA_GpuGemv_Reset();
    WeightResolve_Reset();
    LogitsResidency_Reset();
    MlaStage_Reset();
    StreamPathTiming_Reset();
    StreamTransfer_Reset();
    K2GpuStreamCopy_Reset();
    GenerationOptions opts{};
    opts.maxTokens = (int)tok;
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
    a.mlaUs = SPT_mla().load();
    a.logitsUs = SPT_logits().load();
    a.shardAttnUs = SPT_shardAttn().load();
    a.hostCopyUs = SPT_hostCopy().load();
    a.qkv = MlaStage_QkvUs().load();
    a.kvExp = MlaStage_KvExpandUs().load();
    a.attn = MlaStage_AttnUs().load();
    a.oProj = MlaStage_OProjUs().load();
    a.tryExt = MLA_TryGpuGemvEntries();
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        a.up = vc->GemvWeightUploads() - up0;
        a.hit = vc->WeightContentHits() - hit0;
    }
    a.fb = LivePath_Counters().fallbackCount + e.vulkanGemvFallbackCount();
    a.attnShard = AttnResolveShard();
    a.q6Hit = LogitsPackedResidentHits().load();
    a.hotAlloc = LogitsHotAlloc().load();
    a.cacheEntries = K2LiveCache_Entries();
    return a;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_MOE_ELIMINATE_UNUSED", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_MLA_KV_EXPAND_001", nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    const uint32_t depth = 61, warmTok = 8, timedTok = 8;
    printf("K2_MLA_KV_EXPAND_001\nMODEL=%s DEPTH=%u\n", dir.c_str(), depth);
    printf("LAW=attribute MLA stages; freeze SHARD/LOGITS/MLA-u seals\n");
    if (!fs::is_directory(dir)) {
        printf("K2_MLA_KV_EXPAND_001=SKIP\n");
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
        printf("K2_MLA_KV_EXPAND_001=FAIL open\n");
        _exit(2);
    }
    ElasticDynamicProbe p{};
    ElasticBudget_ProbeHost(p);
    p.layers = depth;
    auto caps = ElasticBudget_Derive(p);
    ElasticBudget_Emit(stdout, caps, p);
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

    printf("\n--- WARM ---\n");
    Arm warm = Run(eng, kPrompt, warmTok, 0, 0);
    printf("WARM ok=%d cacheN=%u\n", warm.ok ? 1 : 0, warm.cacheEntries);
    K2LiveCache_MarkWarm();

    uint64_t up0 = 0, hit0 = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }
    printf("\n--- TIMED ---\n");
    Arm timed = Run(eng, kPrompt, timedTok, up0, hit0);
    MlaStage_Emit(stdout);
    const uint64_t stageSum =
        timed.qkv + timed.kvExp + timed.attn + timed.oProj;
    const char* owner = "QKV_PROJ";
    uint64_t best = timed.qkv;
    if (timed.kvExp > best) {
        best = timed.kvExp;
        owner = "KV_EXPAND";
    }
    if (timed.attn > best) {
        best = timed.attn;
        owner = "ATTN";
    }
    if (timed.oProj > best) {
        best = timed.oProj;
        owner = "O_PROJ";
    }
    const double mlaUpt = timed.tokens ? (double)timed.up / timed.tokens : 1.0;
    const bool freeze =
        timed.ok && warm.ok && timed.shardAttnUs == 0 && timed.attnShard == 0 &&
        timed.hostCopyUs == 0 && mlaUpt == 0.0 && timed.tryExt == 0 &&
        timed.fb == 0 && timed.cacheEntries >= 551 && timed.q6Hit > 0 &&
        timed.hotAlloc == 0;
    // Stage sum should cover most of MLA_COMPUTE (allow 15% misc/overhead).
    const bool attribOk =
        timed.mlaUs > 0 && stageSum > 0 &&
        stageSum >= (timed.mlaUs * 85ull) / 100ull &&
        stageSum <= timed.mlaUs + (timed.mlaUs / 5ull);
    const bool pass = freeze && attribOk && depth == 61;

    printf("TIMED MLA_US=%llu LOGITS_US=%llu STAGE_SUM=%llu OWNER=%s "
           "OWNER_US=%llu\n",
           (unsigned long long)timed.mlaUs, (unsigned long long)timed.logitsUs,
           (unsigned long long)stageSum, owner, (unsigned long long)best);
    printf("FREEZE_OK=%d ATTRIB_OK=%d\n", freeze ? 1 : 0, attribOk ? 1 : 0);
    printf("NEXT_CLIMB=K2_MLA_%s_001\n", owner);
    printf("K2_MLA_KV_EXPAND_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_MLA_KV_EXPAND_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f,
                "QKV=%llu KV_EXPAND=%llu ATTN=%llu O=%llu SUM=%llu MLA=%llu "
                "OWNER=%s\n",
                (unsigned long long)timed.qkv, (unsigned long long)timed.kvExp,
                (unsigned long long)timed.attn, (unsigned long long)timed.oProj,
                (unsigned long long)stageSum, (unsigned long long)timed.mlaUs,
                owner);
        fprintf(f, "K2_MLA_KV_EXPAND_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
