// deep2_live_path_interaction_bounds_cert.cpp — LIVE_PATH_INTERACTION_BOUNDS_001
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "K2LivePathTensorCache.hpp"
#include "LivePathEffect.hpp"
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

struct ArmOut {
    LivePathEffectSnap snap;
    K2LiveCacheStats cache{};
    uint64_t postWarmAllocs = 0;
    uint64_t fallback = 0;
    std::string text;
    bool ok = false;
};

static ArmOut RunArm(bool live, const char* dir, uint32_t nTok, uint32_t depth,
                     const char* prompt) {
    ArmOut o;
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_LIVE_POLICY", "MANUAL");
    _putenv_s("DEEP2_LIVE_POLICY", "MANUAL");
    SetEnvironmentVariableA("DEEP2_LIVE_PATH", live ? "1" : "0");
    _putenv_s("DEEP2_LIVE_PATH", live ? "1" : "0");
    SetEnvironmentVariableA("DEEP2_LIVE_MECH", live ? "all" : "none");
    _putenv_s("DEEP2_LIVE_MECH", live ? "all" : "none");
    SetEnvironmentVariableA("DEEP2_LIVE_FUSED", live ? "1" : "0");
    _putenv_s("DEEP2_LIVE_FUSED", live ? "1" : "0");
#endif
    LivePath_SetEnhancementsEnabled(live);
    LivePath_SetFusedEnabled(live);
    LivePath_ApplyMechEnv();
    StreamTransfer_Reset();
    auto* e = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64; cfg.numKVHeads = 1;
    cfg.vocabSize = 163840; cfg.useMLA = true; cfg.maxSeqLen = 128;
    cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 8;
    if (!e->initialize(cfg) || !e->openK2ShardDirectory(dir)) return o;
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = nTok; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e->runK2NativeStreamPartial(kc);
    o.snap.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    o.snap.tokens = nTok; o.snap.layerDepth = depth;
    o.snap.enhancements = live ? 1u : 0u;
    o.snap.decodeTps = (r.ok && o.snap.wallMs > 0)
        ? ((double)nTok * 1000.0 / o.snap.wallMs) : 0.0;
    o.snap.vramPeak = r.peakResidencyBytes;
    o.snap.streamBytesRead = r.streamBytesRead;
    o.snap.streamBytesToGpu = r.streamBytesToGpu;
    o.snap.cacheHits = r.streamCacheHits;
    o.snap.cacheMisses = r.streamCacheMisses;
    o.snap.streamBytesPerToken = r.streamBytesPerToken;
    LivePath_FillEffectFromCounters(o.snap);
    o.snap.enhancements = live ? 1u : 0u;
    o.cache = K2LiveCache_Snapshot();
    o.postWarmAllocs = StreamTransfer_PostWarmAllocs();
    o.fallback = e->vulkanGemvFallbackCount();
    o.text = r.generatedText;
    o.ok = r.ok;
    return o;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\LIVE_PATH_INTERACTION_BOUNDS_001", nullptr);
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    if (!fs::is_directory(dir)) {
        printf("SKIP_NO_MODEL\nLIVE_PATH_INTERACTION_BOUNDS_001=SKIP\n");
        return 0;
    }
    uint32_t nTok = 8, depth = 4;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS")) nTok = (uint32_t)std::max(4, atoi(t));
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    const uint64_t vramHard = 512ull << 20;
    printf("LIVE_PATH_INTERACTION_BOUNDS_001\nMODEL=%s TOKENS=%u DEPTH=%u\n",
           dir, nTok, depth);
    fflush(stdout);
    ArmOut A = RunArm(false, dir, nTok, depth, kPrompt);
    ArmOut B = RunArm(true, dir, nTok, depth, kPrompt);
    LivePath_EmitEffect(stdout, "A0", A.snap);
    LivePath_EmitEffect(stdout, "B_ALL", B.snap);
    const auto& c = B.cache;
    const int64_t growth = (int64_t)c.bytesPeak - (int64_t)c.bytesAfterWarm;
    const bool budgetOk = c.bytesPeak <= c.budget && c.budget > 0;
    const bool entryOk = c.entriesPeak > 0 && c.entriesPeak <= 4096u;
    const bool outOk = c.outputWeightBytes > 0 && c.outputWeightBytes <= c.budget;
    const bool qOk = B.snap.queuePeak <= 4096u;
    const bool hitsUp = B.snap.cacheHits > A.snap.cacheHits && B.snap.cacheHits > 1000;
    const bool plateau = c.bytesAfterWarm > 0 &&
        (growth <= 0 || growth <= (int64_t)(c.bytesAfterWarm / 50));
    const bool allocOk = B.postWarmAllocs == 0;
    const bool fallbackOk = B.fallback == 0;
    const bool vramOk = B.snap.vramPeak > 0 && B.snap.vramPeak <= vramHard;
    const bool parity = !A.text.empty() && A.text == B.text;
    const bool xferWin = B.snap.streamBytesRead < A.snap.streamBytesRead;
    printf("LIVE_CACHE_BYTES_PEAK=%llu BUDGET=%llu ENTRY_PEAK=%u\n",
           (unsigned long long)c.bytesPeak, (unsigned long long)c.budget, c.entriesPeak);
    printf("OUTPUT_WEIGHT_RESIDENCY=%llu\n", (unsigned long long)c.outputWeightBytes);
    printf("CACHE_HIT_RATE=%.6f CACHE_BYTES_SAVED=%llu\n",
           (c.hits + c.misses) ? (double)c.hits / (double)(c.hits + c.misses) : 0.0,
           (unsigned long long)c.bytesSaved);
    printf("CACHE_EVICTIONS=%llu CACHE_EVICTION_BYTES=%llu\n",
           (unsigned long long)c.evictionCount, (unsigned long long)c.evictionBytes);
    printf("PREFETCH_ACCEPTED=%llu SUPPRESSED=%llu ALREADY=%llu QPEAK=%u\n",
           (unsigned long long)c.prefetchAccepted, (unsigned long long)c.prefetchSuppressed,
           (unsigned long long)c.prefetchAlreadyResident, B.snap.queuePeak);
    printf("RESIDENT_WEIGHT_GROWTH=%lld PER_TOKEN_ALLOCS=%llu FALLBACK=%llu\n",
           (long long)growth, (unsigned long long)B.postWarmAllocs,
           (unsigned long long)B.fallback);
    printf("OUTPUT_PARITY=%d PLATEAU=%d HITS_UP=%d XFER_WIN=%d\n",
           parity ? 1 : 0, plateau ? 1 : 0, hitsUp ? 1 : 0, xferWin ? 1 : 0);
    const bool pass = A.ok && B.ok && budgetOk && entryOk && outOk && qOk &&
        hitsUp && plateau && allocOk && fallbackOk && vramOk && parity && xferWin;
    printf("LIVE_PATH_INTERACTION_BOUNDS_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\LIVE_PATH_INTERACTION_BOUNDS_001\\GATE_STATUS.txt", "w");
    if (f) {
        LivePath_EmitEffect(f, "A0", A.snap);
        LivePath_EmitEffect(f, "B_ALL", B.snap);
        fprintf(f, "LIVE_CACHE_BYTES_PEAK=%llu\n", (unsigned long long)c.bytesPeak);
        fprintf(f, "LIVE_CACHE_BUDGET=%llu\n", (unsigned long long)c.budget);
        fprintf(f, "LIVE_CACHE_ENTRY_PEAK=%u\n", c.entriesPeak);
        fprintf(f, "OUTPUT_WEIGHT_RESIDENCY=%llu\n",
                (unsigned long long)c.outputWeightBytes);
        fprintf(f, "CACHE_BYTES_SAVED=%llu\n", (unsigned long long)c.bytesSaved);
        fprintf(f, "CACHE_EVICTIONS=%llu\n", (unsigned long long)c.evictionCount);
        fprintf(f, "PREFETCH_ACCEPTED=%llu\n", (unsigned long long)c.prefetchAccepted);
        fprintf(f, "PREFETCH_SUPPRESSED=%llu\n", (unsigned long long)c.prefetchSuppressed);
        fprintf(f, "PREFETCH_ALREADY_RESIDENT=%llu\n",
                (unsigned long long)c.prefetchAlreadyResident);
        fprintf(f, "RESIDENT_WEIGHT_GROWTH=%lld\n", (long long)growth);
        fprintf(f, "PER_TOKEN_ALLOCS=%llu\n", (unsigned long long)B.postWarmAllocs);
        fprintf(f, "FALLBACK_COUNT=%llu\n", (unsigned long long)B.fallback);
        fprintf(f, "OUTPUT_PARITY=%d\n", parity ? 1 : 0);
        fprintf(f, "LIVE_PATH_INTERACTION_BOUNDS_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
