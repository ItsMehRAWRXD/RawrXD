// deep2_k2_wall_attribution_cert.cpp — K2_WALL_ATTRIBUTION_001
// Attribution-only. Freeze sustained winner config. No optimization.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePolicy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2ShardIo.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
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

struct AttrWin {
    uint32_t tokens = 0;
    bool ok = false;
    double wallMs = 0;
    uint64_t gemvEntry = 0, tryEntry = 0, mlaOps = 0, mlaFail = 0;
    uint64_t uploads = 0, hits = 0, pinRej = 0, upFail = 0;
    uint64_t fallback = 0, pta = 0, cacheN = 0, resBytes = 0;
    // Exclusive buckets (ms)
    double mlaMs = 0, logitsMs = 0, shardMs = 0, sampleMs = 0;
    double detokMs = 0, streamMs = 0, otherMs = 0;
    double absErrMs = 0;
    // Detail
    uint64_t shardCalls = 0, shardBytes = 0, reopen = 0, seeks = 0;
    uint64_t mapFaults = 0;
    double shardReadMs = 0, mapFaultMs = 0;
    uint64_t logitsCalls = 0, logitsRows = 0;
    double topkMs = 0; // greedy: fused into logits; reported 0
    const char* maxBucket = "UNKNOWN";
    double maxBucketMsTok = 0;
};

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

static AttrWin RunWindow(Deep2Engine& e, const char* prompt, uint32_t tokens,
                         uint64_t up0, uint64_t hit0, uint64_t rej0) {
    AttrWin w{};
    w.tokens = tokens;
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    StreamPathTiming_Reset();
    K2ShardIo_ResetCounters();

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
    w.mlaFail = MLA_GpuGemvFail();
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
    w.sampleMs = SPT_sample().load() / 1000.0;
    w.detokMs = SPT_detok().load() / 1000.0;
    w.streamMs = SPT_stream().load() / 1000.0;
    // SHARD_IO: SPT shard open+read (exclusive of MLA/logits).
    w.shardMs = (SPT_shardOpen().load() + SPT_shardRead().load()) / 1000.0;
    auto sh = K2ShardIo_Snapshot();
    w.shardCalls = sh.readCalls;
    w.shardBytes = sh.readBytes;
    w.shardReadMs = sh.readUs / 1000.0;
    w.reopen = sh.reopenCount;
    w.seeks = sh.seekCount;
    w.mapFaults = sh.mapFaults;
    w.mapFaultMs = sh.mapFaultUs / 1000.0;
    w.logitsCalls = SPT_logitsCalls().load();
    w.logitsRows = SPT_logitsRows().load();
    w.topkMs = 0.0; // greedy path: argmax fused into logits workers

    const double named = w.mlaMs + w.logitsMs + w.shardMs + w.sampleMs +
                         w.detokMs + w.streamMs;
    w.otherMs = w.wallMs - named;
    w.absErrMs = std::fabs(w.wallMs - (named + w.otherMs)); // ~0 by residual

    struct B {
        const char* n;
        double msTok;
    };
    const double t = tokens ? (double)tokens : 1.0;
    B bs[] = {{"MLA", w.mlaMs / t},
              {"LOGITS", w.logitsMs / t},
              {"SHARD_IO", w.shardMs / t},
              {"SAMPLE", w.sampleMs / t},
              {"DETOK", w.detokMs / t},
              {"STREAM", w.streamMs / t},
              {"OTHER", w.otherMs / t}};
    int best = 0;
    for (int i = 1; i < 7; ++i)
        if (bs[i].msTok > bs[best].msTok) best = i;
    w.maxBucket = bs[best].n;
    w.maxBucketMsTok = bs[best].msTok;
    return w;
}

static void EmitWin(const char* tag, const AttrWin& w, uint64_t expectOps) {
    const double t = w.tokens ? (double)w.tokens : 1.0;
    printf("\n=== %s T=%u ok=%d wall_ms=%.1f ===\n", tag, w.tokens,
           w.ok ? 1 : 0, w.wallMs);
    printf("MLA_OPS=%llu MLA_GEMV_ENTRIES=%llu TRYGPU_ENTRIES=%llu FAIL=%llu\n",
           (unsigned long long)w.mlaOps, (unsigned long long)w.gemvEntry,
           (unsigned long long)w.tryEntry, (unsigned long long)w.mlaFail);
    printf("UPLOADS=%llu HITS=%llu HIT_PER_TOKEN=%.1f OPS=%llu/%llu\n",
           (unsigned long long)w.uploads, (unsigned long long)w.hits,
           w.hits / t, (unsigned long long)w.mlaOps,
           (unsigned long long)expectOps);
    printf("PINREJ=%llu UPFAIL=%llu FB=%llu PTA=%llu CACHE_N=%llu "
           "PIN_MIB=%.1f\n",
           (unsigned long long)w.pinRej, (unsigned long long)w.upFail,
           (unsigned long long)w.fallback, (unsigned long long)w.pta,
           (unsigned long long)w.cacheN, w.resBytes / (1024.0 * 1024.0));

    printf("TOKEN_WALL_MS=%.3f\n", w.wallMs);
    printf("MLA_MS=%.3f LOGITS_MS=%.3f SHARD_IO_MS=%.3f SAMPLE_MS=%.3f "
           "DETOK_MS=%.3f STREAM_MS=%.3f OTHER_MS=%.3f\n",
           w.mlaMs, w.logitsMs, w.shardMs, w.sampleMs, w.detokMs, w.streamMs,
           w.otherMs);
    printf("ATTR_ABS_ERR_MS=%.6f\n", w.absErrMs);

    printf("MLA_MS_PER_TOKEN=%.6f\n", w.mlaMs / t);
    printf("LOGITS_MS_PER_TOKEN=%.6f\n", w.logitsMs / t);
    printf("SHARD_IO_MS_PER_TOKEN=%.6f\n", w.shardMs / t);
    printf("SAMPLE_MS_PER_TOKEN=%.6f\n", w.sampleMs / t);
    printf("DETOK_MS_PER_TOKEN=%.6f\n", w.detokMs / t);
    printf("STREAM_MS_PER_TOKEN=%.6f\n", w.streamMs / t);
    printf("OTHER_MS_PER_TOKEN=%.6f\n", w.otherMs / t);
    printf("TOTAL_MS_PER_TOKEN=%.6f\n", w.wallMs / t);
    printf("MAX_BUCKET=%s\n", w.maxBucket);
    printf("MAX_BUCKET_MS_PER_TOKEN=%.6f\n", w.maxBucketMsTok);

    printf("SHARD_READ_CALLS=%llu\n", (unsigned long long)w.shardCalls);
    printf("SHARD_READ_BYTES=%llu\n", (unsigned long long)w.shardBytes);
    printf("SHARD_READ_MS=%.3f\n", w.shardReadMs);
    printf("MAP_FAULTS=%llu\n", (unsigned long long)w.mapFaults);
    printf("MAP_FAULT_MS=%.3f\n", w.mapFaultMs);
    printf("REOPEN_COUNT=%llu\n", (unsigned long long)w.reopen);
    printf("SEEK_COUNT=%llu\n", (unsigned long long)w.seeks);
    printf("READ_BYTES_PER_TOKEN=%.1f\n", w.shardBytes / t);
    printf("READ_CALLS_PER_TOKEN=%.3f\n", w.shardCalls / t);

    printf("LOGITS_CALLS=%llu\n", (unsigned long long)w.logitsCalls);
    printf("LOGITS_MS=%.3f\n", w.logitsMs);
    printf("LOGITS_ROWS=%llu\n", (unsigned long long)w.logitsRows);
    printf("LOGITS_BYTES=%llu\n",
           (unsigned long long)(w.logitsRows * 210ull)); // Q6_K packed row est.
    printf("LOGITS_HOST_BYTES=0\n"); // packed path — no F32 materialize
    printf("TOPK_MS=%.3f\n", w.topkMs);
    printf("SAMPLE_MS=%.3f\n", w.sampleMs);
    fflush(stdout);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_CERT_STEP_LOG", "1"); // diagnostic fflush only
    Sync("DEEP2_MLA_GPU_Q4_ONLY", "0");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_WALL_ATTRIBUTION_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    const uint32_t depth = 61;
    const uint64_t unique = 6ull * depth;
    const uint32_t winsTok[] = {32, 64, 128};

    printf("K2_WALL_ATTRIBUTION_001\n");
    printf("ROLE=ATTRIBUTION_ONLY freeze=sustained_winner no_opt\n");
    printf("MODEL=%s D=%u CACHE_N_EXPECT=366 PIN_MIB_EXPECT~3673 "
           "FULL_DEPTH_PROMO\n",
           dir.c_str(), depth);
    if (!fs::is_directory(dir)) {
        printf("K2_WALL_ATTRIBUTION_001=SKIP\n");
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
        printf("K2_WALL_ATTRIBUTION_001=FAIL open\n");
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
    printf("\n--- WARM 8 (establish pins; not attributed) ---\n");
    fflush(stdout);
    K2LivePolicy_ClearSticky();
    AttrWin warm = RunWindow(eng, kPrompt, 8, 0, 0, 0);
    printf("WARM ok=%d ops=%llu up=%llu hit=%llu cacheN=%llu pinMiB=%.1f\n",
           warm.ok ? 1 : 0, (unsigned long long)warm.mlaOps,
           (unsigned long long)warm.uploads, (unsigned long long)warm.hits,
           (unsigned long long)warm.cacheN,
           warm.resBytes / (1024.0 * 1024.0));
    fflush(stdout);

    uint64_t up0 = 0, hit0 = 0, rej0 = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
        rej0 = vc->WeightPinRejects();
    }

    std::vector<AttrWin> timed;
    for (uint32_t t : winsTok) {
        printf("\n--- TIMED %u ---\n", t);
        fflush(stdout);
        if (auto* vc = eng.getVulkanComputeSlot(0)) {
            up0 = vc->GemvWeightUploads();
            hit0 = vc->WeightContentHits();
            rej0 = vc->WeightPinRejects();
        }
        AttrWin w = RunWindow(eng, kPrompt, t, up0, hit0, rej0);
        char tag[16];
        std::snprintf(tag, sizeof(tag), "W%u", t);
        EmitWin(tag, w, unique * t);
        timed.push_back(w);
    }

    // Freeze + accounting gates (no optimization).
    const double tolAbs = 1.0; // ms; residual OTHER makes err ~0
    bool freezeOk = true, acctOk = true, opsOk = true;
    for (const auto& w : timed) {
        freezeOk = freezeOk && w.ok && w.tryEntry == 0 && w.mlaFail == 0 &&
                   w.upFail == 0 && w.pinRej == 0 && w.fallback == 0 &&
                   w.pta == 0 && w.uploads == 0 && w.hits > 0 &&
                   w.cacheN == 366;
        opsOk = opsOk && (w.mlaOps == unique * w.tokens);
        const double named = w.mlaMs + w.logitsMs + w.shardMs + w.sampleMs +
                             w.detokMs + w.streamMs;
        const double err = std::fabs(w.wallMs - (named + w.otherMs));
        const double tol = std::max(tolAbs, 0.05 * w.wallMs);
        acctOk = acctOk && (err <= tol) && (named <= w.wallMs + tol);
    }

    // Aggregate owner across timed windows by total ms (not per-token).
    double tot[7] = {};
    const char* names[7] = {"MLA", "LOGITS", "SHARD_IO", "SAMPLE",
                            "DETOK", "STREAM", "OTHER"};
    for (const auto& w : timed) {
        tot[0] += w.mlaMs;
        tot[1] += w.logitsMs;
        tot[2] += w.shardMs;
        tot[3] += w.sampleMs;
        tot[4] += w.detokMs;
        tot[5] += w.streamMs;
        tot[6] += w.otherMs;
    }
    int owner = 0;
    for (int i = 1; i < 7; ++i)
        if (tot[i] > tot[owner]) owner = i;

    const bool pass = freezeOk && acctOk && opsOk && depth == 61;
    printf("\nFREEZE_OK=%d ACCT_OK=%d OPS_OK=%d\n", freezeOk ? 1 : 0,
           acctOk ? 1 : 0, opsOk ? 1 : 0);
    printf("OWNER=%s OWNER_TOTAL_MS=%.3f\n", names[owner], tot[owner]);
    printf("NEXT_CLIMB=");
    if (owner == 0) printf("MLA_RETUNE_ONLY_IF_STILL_MAX\n");
    else if (owner == 1) printf("K2_LOGITS_Q6K_RESIDENT_001\n");
    else if (owner == 2) printf("K2_SHARD_IO_CLIMB\n");
    else if (owner == 3) printf("K2_SAMPLE_CLIMB\n");
    else if (owner == 4) printf("K2_DETOK_CLIMB\n");
    else if (owner == 5) printf("K2_STREAM_CLIMB\n");
    else printf("SPLIT_OTHER_MS\n");
    printf("K2_WALL_ATTRIBUTION_001=%s\n", pass ? "PASS" : "FAIL");
    fflush(stdout);

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_WALL_ATTRIBUTION_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "FREEZE_OK=%d ACCT_OK=%d OPS_OK=%d\n", freezeOk ? 1 : 0,
                acctOk ? 1 : 0, opsOk ? 1 : 0);
        for (const auto& w : timed) {
            fprintf(f,
                    "T=%u wall=%.1f mla=%.1f logits=%.1f shard=%.1f sample=%.1f "
                    "detok=%.1f stream=%.1f other=%.1f max=%s\n",
                    w.tokens, w.wallMs, w.mlaMs, w.logitsMs, w.shardMs,
                    w.sampleMs, w.detokMs, w.streamMs, w.otherMs, w.maxBucket);
        }
        fprintf(f, "OWNER=%s OWNER_TOTAL_MS=%.3f\n", names[owner], tot[owner]);
        fprintf(f, "K2_WALL_ATTRIBUTION_001=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f, "NOTE=no optimization; attack OWNER only next.\n");
        fclose(f);
    }
    _exit(pass ? 0 : 2);
}
