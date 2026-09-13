// deep2_k2_serverless_stream_latency_cert.cpp — K2_SERVERLESS_STREAM_LATENCY_001
// Lifecycle buckets only. Freeze winner knobs. No MLA retune.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "MoEEliminate.hpp"
#include "StreamPathTiming.hpp"
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

struct Buckets {
    bool ok = false;
    uint32_t tokens = 0;
    double wallMs = 0;
    uint64_t tokenizeUs = 0, ttftUs = 0, detokUs = 0;
    uint64_t mlaUs = 0, logitsUs = 0, shardUs = 0;
    uint64_t up = 0, hit = 0;
};

static Buckets Run(Deep2Engine& e, const char* prompt, uint32_t tok,
                   uint64_t up0, uint64_t hit0) {
    Buckets b{};
    b.tokens = tok;
    MLA_GpuGemv_Reset();
    StreamPathTiming_Reset();
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
                                  text += t;
                                  return true;
                              });
    b.wallMs = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    b.ok = r.completed && !text.empty() && last >= 0;
    b.tokenizeUs = SPT_tokenize().load();
    b.ttftUs = SPT_ttft().load();
    b.detokUs = SPT_detok().load();
    b.mlaUs = SPT_mla().load();
    b.logitsUs = SPT_logits().load();
    b.shardUs = SPT_shardAttn().load() + SPT_shardMoe().load() +
               SPT_shardOther().load();
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        b.up = vc->GemvWeightUploads() - up0;
        b.hit = vc->WeightContentHits() - hit0;
    }
    return b;
}

static void Print(const char* tag, const Buckets& b) {
    const double decodeUs =
        (b.wallMs * 1000.0) - (double)b.ttftUs; // wall after first token approx
    printf("%s T=%u ok=%d wall_ms=%.1f\n", tag, b.tokens, b.ok ? 1 : 0, b.wallMs);
    printf("  OPEN/ATTACH implied sticky (UP=%llu HIT=%llu)\n",
           (unsigned long long)b.up, (unsigned long long)b.hit);
    printf("  TOKENIZE_US=%llu TTFT_US=%llu DECODE_EST_US=%.0f DETOK_US=%llu\n",
           (unsigned long long)b.tokenizeUs, (unsigned long long)b.ttftUs,
           decodeUs > 0 ? decodeUs : 0.0, (unsigned long long)b.detokUs);
    printf("  MLA_US=%llu LOGITS_US=%llu SHARD_US=%llu\n",
           (unsigned long long)b.mlaUs, (unsigned long long)b.logitsUs,
           (unsigned long long)b.shardUs);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\K2_SERVERLESS_STREAM_LATENCY_001", nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    printf("K2_SERVERLESS_STREAM_LATENCY_001\n");
    printf("LAW=lifecycle buckets; freeze winner; no MLA retune\n");
    if (!fs::is_directory(dir)) {
        printf("K2_SERVERLESS_STREAM_LATENCY_001=SKIP\n");
        _exit(0);
    }

    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_MOE_ELIMINATE_UNUSED", "1");
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
        printf("K2_SERVERLESS_STREAM_LATENCY_001=FAIL open\n");
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
    K2LivePolicy_ClearSticky();

    static const char* kPrompt =
        "Write one short sentence about local decode throughput.";
    printf("\n--- WARM ---\n");
    Buckets warm = Run(eng, kPrompt, 8, 0, 0);
    Print("WARM", warm);
    K2LiveCache_MarkWarm();

    uint64_t up0 = 0, hit0 = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }
    printf("\n--- TIMED ---\n");
    Buckets timed = Run(eng, kPrompt, 8, up0, hit0);
    Print("TIMED", timed);

    const bool sticky = (timed.up == 0) && (timed.hit > 0);
    const bool shard0 = (timed.shardUs == 0);
    const bool ttftOk = (timed.ttftUs > 0) &&
                        ((double)timed.ttftUs <= timed.wallMs * 1000.0);
    const bool pass = timed.ok && warm.ok && sticky && shard0 && ttftOk;

    printf("\nSTICKY=%d SHARD0=%d TTFT_OK=%d\n", sticky ? 1 : 0, shard0 ? 1 : 0,
           ttftOk ? 1 : 0);
    printf("K2_SERVERLESS_STREAM_LATENCY_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_SERVERLESS_STREAM_LATENCY_001\\"
        "GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "ttftUs=%llu wallMs=%.1f up=%llu shardUs=%llu\n",
                (unsigned long long)timed.ttftUs, timed.wallMs,
                (unsigned long long)timed.up, (unsigned long long)timed.shardUs);
        fprintf(f, "K2_SERVERLESS_STREAM_LATENCY_001=%s\n",
                pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
