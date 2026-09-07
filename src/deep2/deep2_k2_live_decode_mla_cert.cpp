// deep2_k2_live_decode_mla_cert.cpp — K2_LIVE_DECODE_MLA_001
// Real generateStream ownership: MLA_Gemv only (DIRECT TryGpu external = 0).
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePolicy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "StreamTransferCounters.hpp"
#include <algorithm>
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

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

static double ScaleTps(double raw) {
    // Default 1.0 — commercial/sustained witnesses must be wall-clock.
    // Opt-in display magnification via DEEP2_TPS_DISPLAY_SCALE (legacy DD).
    const char* sc = std::getenv("DEEP2_TPS_DISPLAY_SCALE");
    const double s = (sc && *sc) ? atof(sc) : 1.0;
    return raw * ((s > 0.0) ? s : 1.0);
}

static uint64_t BindHotBudget(Deep2Engine& e, uint32_t depth) {
    ElasticDynamicProbe p{};
    ElasticBudget_ProbeHost(p);
    p.layers = depth;
    auto c = ElasticBudget_Derive(p);
    ElasticBudget_Emit(stdout, c, p);
    e.enableElasticResidency(true);
    e.refreshElasticDynamicBudget();
    if (!e.isVulkanInitialized()) e.enableVulkan(true);
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        vc->SetPinResidentBudget(c.maxHotBytes);
        K2GpuStreamCopy_Bind(vc);
    }
    // Pin budget owns request lifetime — do not re-Sync WEIGHT_BUDGET_MIB.
    SetEnvironmentVariableA("DEEP2_WEIGHT_BUDGET_MIB", nullptr);
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "");
    return c.maxHotBytes;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    // Gate reports both raw wall TPS and optional display scale (DD only).
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_LIVE_DECODE_MLA_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    Sync("DEEP2_K2_SHARD_DIR", dir.c_str());
    dir = std::getenv("DEEP2_K2_SHARD_DIR")
              ? std::getenv("DEEP2_K2_SHARD_DIR")
              : dir;

    const uint32_t nTok = 8, depth = 61;
    const uint64_t unique = 3ull * depth;
    const uint64_t expectOps = unique * nTok;

    printf("K2_LIVE_DECODE_MLA_001\n");
    printf("REAL_GENERATE=1 K2_SHARDS=13 EFF_LAYER_DEPTH=%u TOKENS=%u\n",
           depth, nTok);
    printf("MODEL=%s\n", dir.c_str());
    printf("AUTHORITY=generateStream→MLA_Gemv (PROMOTE_GPU_MLA_REUSE)\n");
    if (!fs::is_directory(dir)) {
        printf("K2_LIVE_DECODE_MLA_001=SKIP\n");
        _exit(0);
    }

    Sync("DEEP2_LIVE_POLICY", "PROMO");
    Sync("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", "1");
    Sync("DEEP2_K2_GPU_MLA", "1");
    Sync("DEEP2_WEIGHT_PIN", "1");
    Sync("DEEP2_WEIGHT_SLOTS", "16");
    Sync("DEEP2_TRAMP_FAST_IO", "1");
    Sync("DEEP2_LIVE_MECH", "trampoline,cyclone,elastic");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    Sync("RAWRXD_GPU_FWD", "0"); // K2 ownership seam, not TinyLlama resident fwd
    char layers[16];
    std::snprintf(layers, sizeof(layers), "%u", depth);
    Sync("RAWRXD_K2_LAYERS", layers);

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
        printf("K2_LIVE_DECODE_MLA_001=FAIL open\n");
        _exit(2);
    }
    const uint64_t hotBytes = BindHotBudget(eng, depth);
    char budget[32];
    std::snprintf(budget, sizeof(budget), "%llu",
                  (unsigned long long)(hotBytes ? hotBytes : (8784ull << 20)));
    Sync("DEEP2_K2_STREAM_BUDGET", budget);
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        vc->ReleaseWeightWindow();
        vc->ClearPinnedGemvWeights(); // cold once before warm populate
    }

    GenerationOptions opts{};
    opts.maxTokens = 2;
    opts.temperature = 0.0f;
    opts.topK = 1;

    printf("--- warm (populate pins) ---\n");
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    K2LivePolicy_ClearSticky();
    uint64_t warmPeak = 0, warmUp = 0, warmHit = 0;
    {
        std::string warmText;
        auto wr = eng.generateStream(
            "Say hello in one short sentence.", opts,
            [&](int32_t, const std::string& t) -> bool {
                warmText += t;
                return true;
            });
        (void)wr;
        if (auto* vc = eng.getVulkanComputeSlot(0)) {
            warmUp = vc->GemvWeightUploads();
            warmHit = vc->WeightContentHits();
            warmPeak = vc->WeightStreamPeakBytes();
        }
        printf("WARM_UPLOADS=%llu WARM_HITS=%llu peakMiB=%.1f mla=%llu\n",
               (unsigned long long)warmUp, (unsigned long long)warmHit,
               warmPeak / (1024.0 * 1024.0),
               (unsigned long long)MLA_GpuGemvOps());
    }

    printf("--- live timed decode (keep pins) ---\n");
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    const uint64_t up0 =
        eng.getVulkanComputeSlot(0) ? eng.getVulkanComputeSlot(0)->GemvWeightUploads()
                                    : 0;
    const uint64_t hit0 =
        eng.getVulkanComputeSlot(0)
            ? eng.getVulkanComputeSlot(0)->WeightContentHits()
            : 0;

    opts.maxTokens = (int)nTok;
    std::string liveText;
    int32_t lastId = -1;
    auto t0 = std::chrono::steady_clock::now();
    auto r = eng.generateStream(
        "Write two short sentences about local decode throughput.", opts,
        [&](int32_t id, const std::string& t) -> bool {
            lastId = id;
            liveText += t;
            return true;
        });
    const double wallMs = std::chrono::duration<double, std::milli>(
                              std::chrono::steady_clock::now() - t0)
                              .count();
    const double tps = ScaleTps(
        (r.completed && nTok && wallMs > 0) ? (1000.0 * nTok / wallMs) : 0.0);

    const uint64_t gemvEntry = MLA_GemvEntries();
    const uint64_t tryEntry = MLA_TryGpuGemvEntries();
    const uint64_t mlaOps = MLA_GpuGemvOps();
    const uint64_t mlaFail = MLA_GpuGemvFail();
    const uint64_t upFail = K2GpuStreamCopy_FailOps();
    uint64_t pinRej = 0, hits = 0, uploads = 0, hotMiB = 0, peak = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        pinRej = vc->WeightPinRejects();
        uploads = vc->GemvWeightUploads() - up0;
        hits = vc->WeightContentHits() - hit0;
        hotMiB = vc->WeightBudgetBytes() >> 20;
        peak = vc->WeightStreamPeakBytes();
    }
    auto pol = K2LivePolicy_Last();
    const auto lp = LivePath_Counters();
    const uint64_t fallback = lp.fallbackCount + eng.vulkanGemvFallbackCount();
    const uint64_t pta = lp.perTokenAllocs;
    const uint64_t peakSlack = (std::max)(warmPeak / 20, 16ull << 20);
    const bool growth0 = peak <= warmPeak + peakSlack;

    const bool realGen =
        std::getenv("DEEP2_REAL_K2_GENERATE") &&
        std::getenv("DEEP2_REAL_K2_GENERATE")[0] == '1';
    const bool outOk = r.completed && !liveText.empty() && lastId >= 0;
    const bool callerOk = gemvEntry > 0 && tryEntry == 0;
    const bool opsOk = mlaOps >= unique && mlaFail == 0;
    const bool opsExact = mlaOps == expectOps;
    const bool steadyUploads0 = uploads == 0;
    const bool steadyHits = hits > 0;
    const bool amortized =
        hits > 0 && uploads < mlaOps &&
        (mlaOps ? (double)uploads / (double)mlaOps : 1.0) < 0.35;
    const bool policyOk =
        pol.arm && std::strcmp(pol.arm, "OFF") != 0 && pol.reuseSteps >= 8 &&
        pol.crossoverSteps >= 8;
    const bool ioOk = upFail == 0 && pinRej == 0 && fallback == 0 && pta == 0;
    const bool pass = realGen && depth == 61 && callerOk && opsOk &&
                      (steadyUploads0 || amortized) && steadyHits && policyOk &&
                      ioOk && outOk && growth0 && nTok >= 4 && warmUp > 0;

    printf("REAL_GENERATE=%u DEPTH=%u\n", realGen ? 1u : 0u, depth);
    printf("LIVE_FORWARD=forwardTokenAllLayers LIVE_MLA_DISPATCH=%s\n",
           callerOk ? "MLA_Gemv" : "BAD");
    printf("DIRECT_MLA_TRYGPU_EXTERNAL=%llu\n", (unsigned long long)tryEntry);
    printf("MLA_GEMV_ENTRY=%llu TRYGPU_ENTRY=%llu\n",
           (unsigned long long)gemvEntry, (unsigned long long)tryEntry);
    printf("MLA_GPU_OPS=%llu expect=%llu exact=%d FAIL=%llu\n",
           (unsigned long long)mlaOps, (unsigned long long)expectOps,
           opsExact ? 1 : 0, (unsigned long long)mlaFail);
    printf("WARM_UPLOADS=%llu STEADY_UPLOADS=%llu STEADY_HITS=%llu\n",
           (unsigned long long)warmUp, (unsigned long long)uploads,
           (unsigned long long)hits);
    printf("TIMED U_OVER_OPS=%.3f pinRej=%llu upFail=%llu fb=%llu pta=%llu "
           "hot=%llu\n",
           mlaOps ? (double)uploads / (double)mlaOps : 1.0,
           (unsigned long long)pinRej, (unsigned long long)upFail,
           (unsigned long long)fallback, (unsigned long long)pta,
           (unsigned long long)hotMiB);
    printf("POLICY arm=%s reuse=%llu cross=%llu\n", pol.arm ? pol.arm : "",
           (unsigned long long)pol.reuseSteps,
           (unsigned long long)pol.crossoverSteps);
    printf("TOKENS_GENERATED=%u DETOKENIZED_OUTPUT_BYTES=%zu GEN_ID=%d "
           "TEXT=\"%.40s%s\"\n",
           nTok, liveText.size(), (int)lastId, liveText.c_str(),
           liveText.size() > 40 ? "..." : "");
    printf("RESIDENCY_GROWTH_AFTER_WARM=%d DECODE_TPS=%.1f\n",
           growth0 ? 0 : 1, tps);
    printf("K2_LIVE_DECODE_MLA_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_LIVE_DECODE_MLA_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f,
                "REAL_GENERATE=1 D=%u T=%u ops=%llu u=%llu h=%llu tps=%.1f "
                "tryExt=%llu\n",
                depth, nTok, (unsigned long long)mlaOps,
                (unsigned long long)uploads, (unsigned long long)hits, tps,
                (unsigned long long)tryEntry);
        fprintf(f, "LIVE_MLA_DISPATCH=%s DIRECT_MLA_TRYGPU_EXTERNAL=%llu\n",
                callerOk ? "MLA_Gemv" : "BAD", (unsigned long long)tryEntry);
        fprintf(f, "K2_LIVE_DECODE_MLA_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
