// deep2_k2_logits_q6k_resident_cert.cpp — K2_LOGITS_Q6K_RESIDENT_001
// Timed: vocab ResolveWeight cache-hit; SHARD_ATTN/MLA freeze; no F32 warehouse.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "K2LogitsResidency.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2WeightResolve.hpp"
#include "MoEEliminate.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>
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
    double wallMs = 0, logitsMs = 0;
    uint64_t shardAttnB = 0, shardAttnCalls = 0, reopen = 0, mapFault = 0;
    uint64_t keyMiss = 0, hostCopyUs = 0;
    uint64_t up = 0, tryExt = 0, fb = 0;
    uint32_t cacheEntries = 0;
    uint64_t vocabTotal = 0, vocabCache = 0, vocabShard = 0;
    uint64_t vocabShardB = 0, vocabShardCalls = 0;
    uint64_t packedHits = 0, matCalls = 0, f32Wh = 0, shardRows = 0;
    uint64_t parityFail = 0, argmaxCalls = 0;
    std::vector<int32_t> ids;
};

static Arm Run(Deep2Engine& e, const char* prompt, uint32_t tok, uint64_t up0) {
    Arm a{};
    a.tokens = tok;
    MLA_GpuGemv_Reset();
    WeightResolve_Reset();
    LogitsResidency_Reset();
    StreamPathTiming_Reset();
    StreamTransfer_Reset();
    K2GpuStreamCopy_Reset();

    GenerationOptions opts{};
    opts.maxTokens = (int)tok;
    opts.temperature = 0.0f;
    opts.topK = 1;
    std::string text;
    int32_t last = -1;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.generateStream(prompt, opts,
                              [&](int32_t id, const std::string& t) -> bool {
                                  last = id;
                                  a.ids.push_back(id);
                                  text += t;
                                  return true;
                              });
    a.wallMs = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    a.ok = r.completed && !text.empty() && last >= 0;
    a.logitsMs = SPT_logits().load() / 1000.0;
    a.shardAttnB = AttnShardBytes();
    a.shardAttnCalls = AttnShardReadCalls();
    a.reopen = AttnShardReopen();
    a.mapFault = AttnMapFaultCritical();
    a.keyMiss = AttnCacheKeyMiss();
    a.hostCopyUs = SPT_hostCopy().load();
    a.tryExt = MLA_TryGpuGemvEntries();
    a.fb = LivePath_Counters().fallbackCount + e.vulkanGemvFallbackCount();
    if (auto* vc = e.getVulkanComputeSlot(0))
        a.up = vc->GemvWeightUploads() - up0;
    a.cacheEntries = K2LiveCache_Entries();
    a.vocabTotal = VocabResolveTotal();
    a.vocabCache = VocabResolveCache();
    a.vocabShard = VocabResolveShard();
    a.vocabShardB = VocabShardBytes();
    a.vocabShardCalls = VocabShardReadCalls();
    a.packedHits = LogitsPackedResidentHits().load();
    a.matCalls = LogitsFullMaterializeCalls().load();
    a.f32Wh = LogitsF32WarehouseBytes().load();
    a.shardRows = LogitsShardRowReads().load();
    a.parityFail = LogitsParityFail().load();
    a.argmaxCalls = LogitsArgmaxCalls().load();
    return a;
}

static void PrintArm(const char* tag, const Arm& a) {
    const double lpt = a.tokens ? a.logitsMs / a.tokens : 0;
    printf("%s T=%u ok=%d cacheN=%u wall_ms=%.1f\n", tag, a.tokens,
           a.ok ? 1 : 0, a.cacheEntries, a.wallMs);
    printf("  LOGITS_MS=%.3f LOGITS_MS/tok=%.6f ARGMAX=%llu\n", a.logitsMs, lpt,
           (unsigned long long)a.argmaxCalls);
    printf("  VOCAB_RESOLVE cache=%llu/%llu shard=%llu B=%llu calls=%llu\n",
           (unsigned long long)a.vocabCache, (unsigned long long)a.vocabTotal,
           (unsigned long long)a.vocabShard, (unsigned long long)a.vocabShardB,
           (unsigned long long)a.vocabShardCalls);
    printf("  PACKED_HITS=%llu MAT=%llu F32_WH=%llu SHARD_ROWS=%llu "
           "PARITY_FAIL=%llu\n",
           (unsigned long long)a.packedHits, (unsigned long long)a.matCalls,
           (unsigned long long)a.f32Wh, (unsigned long long)a.shardRows,
           (unsigned long long)a.parityFail);
    printf("  FREEZE SHARD_ATTN_B=%llu KEY_MISS=%llu HOST_COPY_US=%llu "
           "MLA_UP=%llu TRY_EXT=%llu FB=%llu\n",
           (unsigned long long)a.shardAttnB, (unsigned long long)a.keyMiss,
           (unsigned long long)a.hostCopyUs, (unsigned long long)a.up,
           (unsigned long long)a.tryExt, (unsigned long long)a.fb);
    WeightResolve_Emit(stdout);
    LogitsResidency_Emit(stdout);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_MOE_ELIMINATE_UNUSED", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_LOGITS_Q6K_RESIDENT_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    const uint32_t depth = 61, warmTok = 8, timedTok = 8;

    printf("K2_LOGITS_Q6K_RESIDENT_001\n");
    printf("MODEL=%s DEPTH=%u WARM=%u TIMED=%u\n", dir.c_str(), depth, warmTok,
           timedTok);
    printf("LAW=ResolveWeight(output.weight) borrow Q6_K; timed vocab shard=0; "
           "no F32 warehouse\n");
    if (!fs::is_directory(dir)) {
        printf("K2_LOGITS_Q6K_RESIDENT_001=SKIP\n");
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
        printf("K2_LOGITS_Q6K_RESIDENT_001=FAIL open\n");
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

    printf("\n--- WARM (install output.weight + attn) ---\n");
    Arm warm = Run(eng, kPrompt, warmTok, 0);
    PrintArm("WARM", warm);
    K2LiveCache_MarkWarm();
    printf("CACHE_ENTRIES_AFTER_WARM=%u\n", K2LiveCache_Entries());

    uint64_t up0 = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0))
        up0 = vc->GemvWeightUploads();

    printf("\n--- TIMED A (vocab resident; freeze attn/MLA) ---\n");
    Arm a = Run(eng, kPrompt, timedTok, up0);
    PrintArm("TIMED_A", a);

    if (auto* vc = eng.getVulkanComputeSlot(0))
        up0 = vc->GemvWeightUploads();
    printf("\n--- TIMED B (semantic identity vs A) ---\n");
    Arm b = Run(eng, kPrompt, timedTok, up0);
    PrintArm("TIMED_B", b);

    const bool freeze =
        (a.shardAttnB == 0) && (a.keyMiss == 0) && (a.hostCopyUs == 0) &&
        (a.up == 0) && (a.tryExt == 0) && (a.fb == 0) &&
        (a.cacheEntries >= 551) && (a.reopen == 0) && (a.mapFault == 0);
    const bool vocabOk = (a.vocabShard == 0) && (a.vocabShardB == 0) &&
                         (a.vocabShardCalls == 0) && (a.vocabCache > 0) &&
                         (a.vocabCache == a.vocabTotal);
    const bool noWh = (a.matCalls == 0) && (a.f32Wh == 0) && (a.shardRows == 0);
    const bool packed = (a.packedHits > 0) && (a.argmaxCalls > 0) &&
                        (a.parityFail == 0);
    const bool semOk = a.ok && b.ok && a.ids.size() == b.ids.size() &&
                       a.ids == b.ids;
    const bool pass = warm.ok && freeze && vocabOk && noWh && packed && semOk &&
                      depth == 61;

    printf("\nLOGITS_MS_PER_TOKEN_A=%.6f LOGITS_MS_PER_TOKEN_B=%.6f\n",
           a.tokens ? a.logitsMs / a.tokens : 0,
           b.tokens ? b.logitsMs / b.tokens : 0);
    printf("FREEZE_OK=%d VOCAB_RESIDENT=%d NO_WAREHOUSE=%d PACKED=%d "
           "SEMANTIC_ID=%d\n",
           freeze ? 1 : 0, vocabOk ? 1 : 0, noWh ? 1 : 0, packed ? 1 : 0,
           semOk ? 1 : 0);
    printf("K2_LOGITS_Q6K_RESIDENT_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_LOGITS_Q6K_RESIDENT_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "vocabCache=%llu vocabShardB=%llu mat=%llu f32=%llu\n",
                (unsigned long long)a.vocabCache,
                (unsigned long long)a.vocabShardB,
                (unsigned long long)a.matCalls, (unsigned long long)a.f32Wh);
        fprintf(f, "LOGITS_MS/tok=%.6f freeze=%d sem=%d\n",
                a.tokens ? a.logitsMs / a.tokens : 0, freeze ? 1 : 0,
                semOk ? 1 : 0);
        fprintf(f, "K2_LOGITS_Q6K_RESIDENT_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
