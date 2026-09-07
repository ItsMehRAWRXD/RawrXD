// deep2_live_path_effectiveness_cert.cpp — LIVE_PATH_EFFECTIVENESS_001 A/B
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "LivePathEffect.hpp"
#include "StreamTransferCounters.hpp"
#include "WarmupScheduler.hpp"
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

static uint64_t CorpusBytes(const char* dir) {
    uint64_t n = 0;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(dir, ec);
         !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (it->is_regular_file(ec)) n += (uint64_t)it->file_size(ec);
    }
    return n;
}

static LivePathEffectSnap RunArm(bool liveOn, const char* dir, uint32_t nTok,
                                 uint32_t depth, const char* prompt) {
    LivePathEffectSnap s;
    s.tokens = nTok;
    s.layerDepth = depth;
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_LIVE_POLICY", "MANUAL");
    _putenv_s("DEEP2_LIVE_POLICY", "MANUAL");
    SetEnvironmentVariableA("DEEP2_LIVE_PATH", liveOn ? "1" : "0");
    _putenv_s("DEEP2_LIVE_PATH", liveOn ? "1" : "0");
#endif
    LivePath_SetEnhancementsEnabled(liveOn);
    StreamTransfer_Reset();
    auto* e = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64; cfg.numKVHeads = 1;
    cfg.vocabSize = 163840; cfg.useMLA = true; cfg.maxSeqLen = 128;
    cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 8;
    if (!e->initialize(cfg) || !e->openK2ShardDirectory(dir)) {
        s.decodeTps = -1; return s;
    }
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = nTok; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e->runK2NativeStreamPartial(kc);
    s.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    s.decodeTps = (r.ok && s.wallMs > 0) ? ((double)nTok * 1000.0 / s.wallMs) : 0.0;
    s.vramPeak = r.peakResidencyBytes;
    s.residentWeightPeak = r.peakResidencyBytes;
    s.streamBytesRead = r.streamBytesRead;
    s.streamBytesToGpu = r.streamBytesToGpu;
    s.streamBytesRecon = r.streamBytesReconstructed;
    s.streamReadOps = r.streamReadOps;
    s.streamGpuUploadOps = r.streamGpuUploadOps;
    s.streamBytesPerToken = r.streamBytesPerToken;
    s.cacheHits = r.streamCacheHits;
    s.cacheMisses = r.streamCacheMisses;
    s.perTokenAllocs = StreamTransfer_Snapshot().allocOps;
    s.fallbackCount = e->vulkanGemvFallbackCount();
    LivePath_FillEffectFromCounters(s);
    const auto& ws = e->getWarmupStats();
    s.expertHits = ws.prefetchesHit;
    s.expertAccesses = ws.totalPredictions;
    s.expertPrefetches = ws.prefetchesIssued;
    s.enhancements = liveOn ? 1u : 0u;
    if (!r.ok) s.decodeTps = 0;
    return s;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\LIVE_PATH_EFFECTIVENESS_001", nullptr);
    if (!fs::is_directory(dir)) {
        printf("SKIP_NO_MODEL\nLIVE_PATH_EFFECTIVENESS_001=SKIP\n");
        return 0;
    }
    uint32_t nTok = 4, depth = 4;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS")) nTok = (uint32_t)std::max(2, atoi(t));
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    const uint64_t corpus = CorpusBytes(dir);
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    printf("LIVE_PATH_EFFECTIVENESS_001\nMODEL=%s\n", dir);
    printf("CORPUS_BYTES=%llu CORPUS_GIB=%.2f\n", (unsigned long long)corpus,
           corpus / (1024.0 * 1024.0 * 1024.0));
    printf("TOKENS=%u DEPTH=%u (transfer≠corpus)\n", nTok, depth);
    LivePathEffectSnap A = RunArm(false, dir, nTok, depth, kPrompt);
    LivePathEffectSnap B = RunArm(true, dir, nTok, depth, kPrompt);
    LivePath_EmitEffect(stdout, "A_MIN", A);
    LivePath_EmitEffect(stdout, "B_FULL", B);
    auto dlt = LivePath_ComputeDelta(A, B);
    LivePath_EmitDelta(stdout, dlt);
    // Effect succeeds when live reduces transfer or raises TPS (or both).
    const bool xferWin = B.streamBytesRead < A.streamBytesRead && A.streamBytesRead > 0;
    const bool hitWin = B.cacheHits > A.cacheHits;
    const bool tpsWin = B.decodeTps > A.decodeTps && A.decodeTps >= 0;
    const bool okRun = A.decodeTps >= 0 && B.decodeTps > 0;
    const bool pass = okRun && (xferWin || hitWin) && (tpsWin || xferWin);
    printf("EFFECT xferWin=%d hitWin=%d tpsWin=%d\n", xferWin, hitWin, tpsWin);
    printf("LIVE_PATH_EFFECTIVENESS_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\LIVE_PATH_EFFECTIVENESS_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "CORPUS_BYTES=%llu\n", (unsigned long long)corpus);
        LivePath_EmitEffect(f, "A_MIN", A);
        LivePath_EmitEffect(f, "B_FULL", B);
        LivePath_EmitDelta(f, dlt);
        fprintf(f, "EFFECT xferWin=%d hitWin=%d tpsWin=%d\n", xferWin, hitWin, tpsWin);
        fprintf(f, "LIVE_PATH_EFFECTIVENESS_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
