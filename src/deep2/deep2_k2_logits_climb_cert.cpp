// deep2_k2_logits_climb_cert.cpp — K2_LOGITS_CLIMB_001
// Packed Q6_K fused argmax climb. Freeze MLA/cache. Then wall attribution 002.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePolicy.hpp"
#include "K2LogitsClimb.hpp"
#include "K2LogitsResidency.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2ShardIo.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include <chrono>
#include <cmath>
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

struct Win {
    uint32_t tokens = 0;
    bool ok = false;
    double wallMs = 0;
    uint64_t gemvEntry = 0, tryEntry = 0, mlaOps = 0;
    uint64_t uploads = 0, hits = 0, pinRej = 0, upFail = 0;
    uint64_t fallback = 0, pta = 0, cacheN = 0, resBytes = 0;
    double mlaMs = 0, logitsMs = 0, shardMs = 0;
    uint64_t parityFail = 0;
    LogitsClimbSnap climb{};
};

static Win RunWindow(Deep2Engine& e, const char* prompt, uint32_t tokens,
                     uint64_t up0, uint64_t hit0, uint64_t rej0) {
    Win w{};
    w.tokens = tokens;
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    StreamPathTiming_Reset();
    K2ShardIo_ResetCounters();
    LogitsClimb_Reset();
    LogitsResidency_Reset();

    GenerationOptions opts{};
    opts.maxTokens = (int)tokens;
    opts.temperature = 0.0f;
    opts.topK = 1;
    std::string text;
    int32_t lastId = -1;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.generateStream(prompt, opts,
                              [&](int32_t id, const std::string& t) -> bool {
                                  lastId = id;
                                  text += t;
                                  return true;
                              });
    w.wallMs = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    w.ok = r.completed && !text.empty() && lastId >= 0;
    w.gemvEntry = MLA_GemvEntries();
    w.tryEntry = MLA_TryGpuGemvEntries();
    w.mlaOps = MLA_GpuGemvOps();
    w.upFail = K2GpuStreamCopy_FailOps();
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        w.uploads = vc->GemvWeightUploads() - up0;
        w.hits = vc->WeightContentHits() - hit0;
        w.pinRej = vc->WeightPinRejects() - rej0;
        w.cacheN = vc->WeightPinCacheCount();
        w.resBytes = vc->WeightPinResidentBytes();
    }
    auto lp = LivePath_Counters();
    w.fallback = lp.fallbackCount + e.vulkanGemvFallbackCount();
    w.pta = lp.perTokenAllocs;
    w.mlaMs = SPT_mla().load() / 1000.0;
    w.logitsMs = SPT_logits().load() / 1000.0;
    w.shardMs = (SPT_shardOpen().load() + SPT_shardRead().load()) / 1000.0;
    w.parityFail = LogitsParityFail().load();
    w.climb = LogitsClimb_Snapshot();
    return w;
}

static void Emit(const char* tag, const Win& w, uint64_t expectOps) {
    const double t = w.tokens ? (double)w.tokens : 1.0;
    printf("\n=== %s T=%u ok=%d wall_ms=%.1f ===\n", tag, w.tokens,
           w.ok ? 1 : 0, w.wallMs);
    printf("MLA_OPS=%llu TRYGPU_ENTRIES=%llu UPLOADS=%llu HITS=%llu "
           "HIT_PER_TOKEN=%.1f OPS=%llu/%llu\n",
           (unsigned long long)w.mlaOps, (unsigned long long)w.tryEntry,
           (unsigned long long)w.uploads, (unsigned long long)w.hits,
           w.hits / t, (unsigned long long)w.mlaOps,
           (unsigned long long)expectOps);
    printf("PINREJ=%llu UPFAIL=%llu FB=%llu PTA=%llu CACHE_N=%llu "
           "PIN_MIB=%.1f\n",
           (unsigned long long)w.pinRej, (unsigned long long)w.upFail,
           (unsigned long long)w.fallback, (unsigned long long)w.pta,
           (unsigned long long)w.cacheN, w.resBytes / (1024.0 * 1024.0));
    printf("MLA_MS_PER_TOKEN=%.6f\n", w.mlaMs / t);
    printf("LOGITS_MS_PER_TOKEN=%.6f\n", w.logitsMs / t);
    printf("SHARD_IO_MS_PER_TOKEN=%.6f\n", w.shardMs / t);
    printf("TOTAL_MS_PER_TOKEN=%.6f\n", w.wallMs / t);
    printf("PARITY_FAIL=%llu\n", (unsigned long long)w.parityFail);
    LogitsClimb_Emit(stdout);
    LogitsResidency_Emit(stdout);
    fflush(stdout);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_CERT_STEP_LOG", "1");
    Sync("DEEP2_MLA_GPU_Q4_ONLY", "0");
    Sync("DEEP2_LOGITS_LEGACY", "0");
    Sync("DEEP2_LOGITS_PARITY", "1"); // one serial check on first logits call
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_LOGITS_CLIMB_001", nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    const uint32_t depth = 61;
    const uint64_t unique = 6ull * depth;
    const uint32_t winsTok[] = {32, 64, 128};

    printf("K2_LOGITS_CLIMB_001\n");
    printf("ROLE=LOGITS_CLIMB fused_q6k_argmax freeze=MLA/cache\n");
    printf("MODEL=%s D=%u TARGET_LOGITS_MS_TOK<200\n", dir.c_str(), depth);
    if (!fs::is_directory(dir)) {
        printf("K2_LOGITS_CLIMB_001=SKIP\n");
        _exit(0);
    }

    Sync("DEEP2_LIVE_POLICY", "PROMO");
    Sync("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", "1");
    Sync("DEEP2_K2_GPU_MLA", "1");
    Sync("DEEP2_WEIGHT_PIN", "1");
    Sync("DEEP2_WEIGHT_PREFETCH", "0");
    Sync("DEEP2_WEIGHT_OVERLAP", "0");
    Sync("DEEP2_LIVE_MECH", "trampoline,cyclone,elastic");
    Sync("DEEP2_TRAMP_FAST_IO", "1");
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
    cfg.maxSeqLen = 512;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_LOGITS_CLIMB_001=FAIL open\n");
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
    char budget[32];
    std::snprintf(budget, sizeof(budget), "%llu",
                  (unsigned long long)(caps.maxHotBytes ? caps.maxHotBytes
                                                        : (8784ull << 20)));
    Sync("DEEP2_K2_STREAM_BUDGET", budget);
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        vc->SetPinResidentBudget(caps.maxHotBytes);
        vc->ReleaseWeightWindow();
        vc->ClearPinnedGemvWeights();
        K2GpuStreamCopy_Bind(vc);
    }

    static const char* kPrompt =
        "Write a short paragraph on local decode throughput.";
    printf("\n--- WARM 8 ---\n");
    fflush(stdout);
    K2LivePolicy_ClearSticky();
    Win warm = RunWindow(eng, kPrompt, 8, 0, 0, 0);
    printf("WARM ok=%d cacheN=%llu pinMiB=%.1f logits_ms/tok=%.1f\n",
           warm.ok ? 1 : 0, (unsigned long long)warm.cacheN,
           warm.resBytes / (1024.0 * 1024.0),
           warm.logitsMs / (warm.tokens ? warm.tokens : 1));
    fflush(stdout);

    uint64_t up0 = 0, hit0 = 0, rej0 = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
        rej0 = vc->WeightPinRejects();
    }

    bool allOk = warm.ok;
    double maxLogitsMsTok = 0.0;
    int argmaxParity = 1;
    for (uint32_t tok : winsTok) {
        char tag[32];
        std::snprintf(tag, sizeof(tag), "W%u", tok);
        Win w = RunWindow(eng, kPrompt, tok, up0, hit0, rej0);
        Emit(tag, w, unique * tok);
        const double lpt = w.logitsMs / (w.tokens ? w.tokens : 1);
        if (lpt > maxLogitsMsTok) maxLogitsMsTok = lpt;
        if (!w.ok || w.tryEntry != 0 || w.uploads != 0 || w.cacheN != 366 ||
            w.parityFail != 0 || w.climb.allocCount != 0 ||
            w.climb.fullMaterialize != 0 || w.climb.fullDequant != 0 ||
            w.climb.rowsVisited != (uint64_t)w.tokens * 163840ull ||
            w.mlaOps != unique * tok ||
            (w.hits / (double)w.tokens) < 365.5) {
            allOk = false;
        }
        if (w.parityFail) argmaxParity = 0;
        if (auto* vc = eng.getVulkanComputeSlot(0)) {
            up0 = vc->GemvWeightUploads();
            hit0 = vc->WeightContentHits();
            rej0 = vc->WeightPinRejects();
        }
    }

    const int hotAllocOk = LogitsHotAlloc().load() == 0 ? 1 : 0;
    const int logitsReduced = maxLogitsMsTok < 200.0 ? 1 : 0;
    const int pass =
        allOk && argmaxParity && hotAllocOk && logitsReduced ? 1 : 0;

    printf("\nARGMAX_PARITY=%d\n", argmaxParity);
    printf("LOGITS_FULL_MATERIALIZE=%llu\n",
           (unsigned long long)warm.climb.fullMaterialize);
    printf("Q6_FULL_DEQUANT=%llu\n",
           (unsigned long long)warm.climb.fullDequant);
    printf("HOT_ALLOC=%d\n", hotAllocOk ? 0 : 1);
    printf("LOGITS_MS_PER_TOK_MAX=%.3f\n", maxLogitsMsTok);
    printf("LOGITS_TARGET_MET=%d\n", logitsReduced);
    printf("K2_LOGITS_CLIMB_001=%s\n", pass ? "PASS" : "FAIL");
    fflush(stdout);

    FILE* gs = nullptr;
    fopen_s(&gs, "G:\\~dev\\rawrxd\\evidence\\K2_LOGITS_CLIMB_001\\GATE_STATUS.txt",
            "w");
    if (gs) {
        std::fprintf(gs, "K2_LOGITS_CLIMB_001=%s\n", pass ? "PASS" : "FAIL");
        std::fprintf(gs, "ARGMAX_PARITY=%d\n", argmaxParity);
        std::fprintf(gs, "LOGITS_MS_PER_TOK_MAX=%.3f\n", maxLogitsMsTok);
        std::fprintf(gs, "HOT_ALLOC=%d\n", hotAllocOk ? 0 : 1);
        std::fclose(gs);
    }
    _exit(pass ? 0 : 1);
}
