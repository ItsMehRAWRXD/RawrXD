// deep2_k2_shard_attn_residency_cert.cpp — K2_SHARD_ATTN_RESIDENCY_001
// Timed arm: SHARD_ATTN reread = 0; borrow retained cache; MLA U/tok = 0.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
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
    uint64_t shardAttnUs = 0, hostCopyUs = 0, mlaUs = 0;
    uint64_t up = 0, hit = 0, tryExt = 0, fb = 0;
    uint64_t attnTotal = 0, attnCache = 0, attnShard = 0;
    uint64_t keyMiss = 0, genMiss = 0, wsVeto = 0;
    uint64_t typeMis = 0, rangeMis = 0;
    uint64_t borrowB = 0, shardB = 0, shardCalls = 0, reopen = 0;
    uint64_t mapFault = 0;
    uint32_t cacheEntries = 0;
};

static Arm Run(Deep2Engine& e, const char* prompt, uint32_t tok, uint64_t up0,
               uint64_t hit0) {
    Arm a{};
    a.tokens = tok;
    MLA_GpuGemv_Reset();
    WeightResolve_Reset();
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
    a.shardAttnUs = SPT_shardAttn().load();
    a.hostCopyUs = SPT_hostCopy().load();
    a.mlaUs = SPT_mla().load();
    a.tryExt = MLA_TryGpuGemvEntries();
    a.up = 0;
    a.hit = 0;
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        a.up = vc->GemvWeightUploads() - up0;
        a.hit = vc->WeightContentHits() - hit0;
    }
    a.fb = LivePath_Counters().fallbackCount + e.vulkanGemvFallbackCount();
    a.attnTotal = AttnResolveTotal();
    a.attnCache = AttnResolveCache();
    a.attnShard = AttnResolveShard();
    a.keyMiss = AttnCacheKeyMiss();
    a.genMiss = AttnCacheGenMiss();
    a.wsVeto = AttnCacheWsVeto();
    a.typeMis = AttnCacheTypeMismatch();
    a.rangeMis = AttnCacheRangeMismatch();
    a.borrowB = AttnBorrowBytes();
    a.shardB = AttnShardBytes();
    a.shardCalls = AttnShardReadCalls();
    a.reopen = AttnShardReopen();
    a.mapFault = AttnMapFaultCritical();
    a.cacheEntries = K2LiveCache_Entries();
    return a;
}

static void PrintArm(const char* tag, const Arm& a) {
    const double bpt = a.tokens ? (double)a.shardB / a.tokens : 0;
    const double cpt = a.tokens ? (double)a.shardCalls / a.tokens : 0;
    const double upt = a.tokens ? (double)a.up / a.tokens : 0;
    printf("%s T=%u ok=%d cacheN=%u\n", tag, a.tokens, a.ok ? 1 : 0,
           a.cacheEntries);
    printf("  SHARD_ATTN_US=%llu HOST_CACHE_COPY_US=%llu MLA_US=%llu\n",
           (unsigned long long)a.shardAttnUs, (unsigned long long)a.hostCopyUs,
           (unsigned long long)a.mlaUs);
    printf("  SHARD_ATTN_BYTES=%llu /tok=%.1f CALLS=%llu /tok=%.3f REOPEN=%llu "
           "MAPFAULT=%llu\n",
           (unsigned long long)a.shardB, bpt, (unsigned long long)a.shardCalls,
           cpt, (unsigned long long)a.reopen, (unsigned long long)a.mapFault);
    printf("  MLA_UP=%llu /tok=%.3f HIT=%llu TRY_EXT=%llu FB=%llu\n",
           (unsigned long long)a.up, upt, (unsigned long long)a.hit,
           (unsigned long long)a.tryExt, (unsigned long long)a.fb);
    WeightResolve_Emit(stdout);
    const uint64_t parts =
        a.attnCache + a.keyMiss + a.genMiss + a.wsVeto + a.typeMis + a.rangeMis;
    // wsVeto is secondary (put fail after key miss already counted) — exclude
    // from identity when double-counted; primary partition = cache+key(+…).
    const uint64_t primary = a.attnCache + a.keyMiss + a.genMiss + a.typeMis +
                             a.rangeMis;
    printf("  PARTITION total=%llu primary=%llu (cache+key+gen+type+range) "
           "wsVeto=%llu\n",
           (unsigned long long)a.attnTotal, (unsigned long long)primary,
           (unsigned long long)a.wsVeto);
    (void)parts;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_MOE_ELIMINATE_UNUSED", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_SHARD_ATTN_RESIDENCY_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    const uint32_t depth = 61, warmTok = 8, timedTok = 8;

    printf("K2_SHARD_ATTN_RESIDENCY_001\n");
    printf("MODEL=%s DEPTH=%u WARM=%u TIMED=%u\n", dir.c_str(), depth, warmTok,
           timedTok);
    printf("LAW=ResolveWeight borrow retained; timed SHARD_ATTN=0\n");
    if (!fs::is_directory(dir)) {
        printf("K2_SHARD_ATTN_RESIDENCY_001=SKIP\n");
        _exit(0);
    }

    Sync("DEEP2_LIVE_POLICY", "PROMO");
    Sync("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", "0"); // WINNER frozen — pin owns
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
        printf("K2_SHARD_ATTN_RESIDENCY_001=FAIL open\n");
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

    printf("\n--- WARM (populate retained attn cache) ---\n");
    Arm warm = Run(eng, kPrompt, warmTok, 0, 0);
    PrintArm("WARM", warm);
    K2LiveCache_MarkWarm();
    printf("CACHE_ENTRIES_AFTER_WARM=%u BYTES=%llu\n", K2LiveCache_Entries(),
           (unsigned long long)K2LiveCache_Bytes());

    uint64_t up0 = 0, hit0 = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }

    printf("\n--- TIMED (pins+cache hot; SHARD_ATTN must be 0) ---\n");
    Arm timed = Run(eng, kPrompt, timedTok, up0, hit0);
    PrintArm("TIMED", timed);

    const double shardBpt =
        timed.tokens ? (double)timed.shardB / timed.tokens : 1.0;
    const double shardCpt =
        timed.tokens ? (double)timed.shardCalls / timed.tokens : 1.0;
    const double mlaUpt = timed.tokens ? (double)timed.up / timed.tokens : 1.0;
    const uint64_t primary = timed.attnCache + timed.keyMiss + timed.genMiss +
                             timed.typeMis + timed.rangeMis;
    const bool partOk = (timed.attnTotal == primary);
    const bool shard0 = (timed.shardB == 0) && (timed.shardCalls == 0) &&
                        (timed.reopen == 0) && (timed.mapFault == 0) &&
                        (shardBpt == 0.0) && (shardCpt == 0.0);
    const bool mlaOk = (mlaUpt == 0.0) && (timed.hit > 0);
    const bool copy0 = (timed.hostCopyUs == 0);
    const bool try0 = (timed.tryExt == 0);
    const bool fb0 = (timed.fb == 0);
    const bool cacheLive = (timed.cacheEntries >= 100);
    const bool pass = timed.ok && warm.ok && shard0 && mlaOk && copy0 && try0 &&
                      fb0 && partOk && cacheLive && depth == 61;

    printf("\nTIMED_SHARD_ATTN_BPT=%.3f CALLS_PT=%.3f REOPEN=%llu MAPFAULT=%llu\n",
           shardBpt, shardCpt, (unsigned long long)timed.reopen,
           (unsigned long long)timed.mapFault);
    printf("MLA_UP_PT=%.3f HOST_COPY_US=%llu TRY_EXT=%llu FB=%llu "
           "PARTITION_OK=%d\n",
           mlaUpt, (unsigned long long)timed.hostCopyUs,
           (unsigned long long)timed.tryExt, (unsigned long long)timed.fb,
           partOk ? 1 : 0);
    if (!shard0) {
        printf("DOMINANT_MISS KEY=%llu GEN=%llu WS=%llu TYPE=%llu RANGE=%llu\n",
               (unsigned long long)timed.keyMiss,
               (unsigned long long)timed.genMiss,
               (unsigned long long)timed.wsVeto,
               (unsigned long long)timed.typeMis,
               (unsigned long long)timed.rangeMis);
    }
    printf("K2_SHARD_ATTN_RESIDENCY_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_SHARD_ATTN_RESIDENCY_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "TIMED shardB=%llu calls=%llu reopen=%llu mapfault=%llu\n",
                (unsigned long long)timed.shardB,
                (unsigned long long)timed.shardCalls,
                (unsigned long long)timed.reopen,
                (unsigned long long)timed.mapFault);
        fprintf(f, "keyMiss=%llu cache=%llu total=%llu hostCopyUs=%llu\n",
                (unsigned long long)timed.keyMiss,
                (unsigned long long)timed.attnCache,
                (unsigned long long)timed.attnTotal,
                (unsigned long long)timed.hostCopyUs);
        fprintf(f, "K2_SHARD_ATTN_RESIDENCY_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
