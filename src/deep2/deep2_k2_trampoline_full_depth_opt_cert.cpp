// deep2_k2_trampoline_full_depth_opt_cert.cpp — K2_TRAMPOLINE_FULL_DEPTH_OPT_001
// A=legacy ifstream IO | B=persistent Win32 shard handles (opt winner path)
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2ShardIo.hpp"
#include "LivePathEffect.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
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
    LivePathEffectSnap s;
    K2LiveCacheStats cache{};
    std::string response; // whatever the engine returned (not predefined text)
    int32_t lastTok = -1;
    bool liveActiveAfter = true;
};

static ArmOut RunTramp(const char* fastIo, const char* dir, uint32_t nTok,
                       uint32_t depth, const char* prompt) {
    ArmOut o;
    o.s.tokens = nTok; o.s.layerDepth = depth;
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_LIVE_POLICY", "MANUAL");
    _putenv_s("DEEP2_LIVE_POLICY", "MANUAL");
    SetEnvironmentVariableA("DEEP2_LIVE_PATH", "1");
    _putenv_s("DEEP2_LIVE_PATH", "1");
    SetEnvironmentVariableA("DEEP2_LIVE_MECH", "trampoline");
    _putenv_s("DEEP2_LIVE_MECH", "trampoline");
    SetEnvironmentVariableA("DEEP2_LIVE_FUSED", "0");
    _putenv_s("DEEP2_LIVE_FUSED", "0");
    SetEnvironmentVariableA("DEEP2_TRAMP_FAST_IO", fastIo);
    _putenv_s("DEEP2_TRAMP_FAST_IO", fastIo);
#endif
    K2ShardIo_SetEnabled(fastIo[0] == '1');
    LivePath_SetEnhancementsEnabled(true);
    LivePath_SetFusedEnabled(false);
    LivePath_ApplyMechEnv();
    StreamTransfer_Reset();
    StreamPathTiming_Reset();
    auto* e = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64; cfg.numKVHeads = 1;
    cfg.vocabSize = 163840; cfg.useMLA = true; cfg.maxSeqLen = 256;
    cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 8;
    if (!e->initialize(cfg) || !e->openK2ShardDirectory(dir)) {
        o.s.decodeTps = -1; return o;
    }
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = nTok; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e->runK2NativeStreamPartial(kc);
    o.s.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    o.s.decodeTps = (r.ok && o.s.wallMs > 0)
        ? ((double)nTok * 1000.0 / o.s.wallMs) : 0.0;
    o.s.vramPeak = r.peakResidencyBytes;
    o.s.streamBytesRead = r.streamBytesRead;
    o.s.streamBytesPerToken = r.streamBytesPerToken;
    o.s.cacheHits = r.streamCacheHits;
    o.s.fallbackCount = e->vulkanGemvFallbackCount();
    LivePath_FillEffectFromCounters(o.s);
    o.cache = K2LiveCache_Snapshot();
    o.response = std::move(r.generatedText);
    o.lastTok = r.generatedTokenId;
    o.liveActiveAfter = LivePath_Active();
    if (!r.ok) {
        o.s.decodeTps = 0;
        if (!r.error.empty())
            fprintf(stderr, "ARM_ERROR fastIo=%s: %s\n", fastIo, r.error.c_str());
    }
    return o;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    // This cert measures CPU trampoline+fused Q4_K^T — keep GPU MLA off.
    _putenv_s("DEEP2_K2_GPU_MLA", "0");
    _putenv_s("DEEP2_K2_GPU_STREAM_COPY", "0");
    // One white face: no enhancement bandwidth thieves on trampoline OPT.
    _putenv_s("RAWRXD_ENHANCE_SKIP",
              "mars,medusa,nu,warmup,ckv,nvme,slide,chamber,plasma,sov,torus,"
              "prefetch,telemetry,elastic,cyclone");
    // Q then KV; gemv pool owns cores (no Q∥KV × 8 nest).
    _putenv_s("DEEP2_MLA_SERIAL", "1");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    if (!fs::is_directory(dir)) {
        printf("SKIP_NO_MODEL\nK2_TRAMPOLINE_FULL_DEPTH_OPT_001=SKIP\n");
        return 0;
    }
    uint32_t nTok = 2, depth = 61;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS"))
        nTok = (uint32_t)std::max(1, atoi(t));
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    printf("K2_TRAMPOLINE_FULL_DEPTH_OPT_001\nMODEL=%s TOKENS=%u DEPTH=%u\n",
           dir, nTok, depth);
    printf("FROZEN_B2_FLOOR=0.095 PROMOTION=0.09785\n");
    ArmOut A = RunTramp("0", dir, nTok, depth, kPrompt); // legacy ifstream
    LivePath_EmitEffect(stdout, "A_LEGACY_IO", A.s);
    StreamPathTiming_Emit(stdout);
    fprintf(stdout, "TRAMP_HITS=%llu LAYER_ACQ=%llu DUP=%llu ACTIVE=%u\n",
            (unsigned long long)A.cache.trampOutHits,
            (unsigned long long)A.cache.cycloneLayerAcquires,
            (unsigned long long)A.cache.combinedDupAcquires,
            A.liveActiveAfter ? 1u : 0u);
    ArmOut B = RunTramp("1", dir, nTok, depth, kPrompt); // fast IO
    LivePath_EmitEffect(stdout, "B_FAST_IO", B.s);
    StreamPathTiming_Emit(stdout);
    fprintf(stdout, "TRAMP_HITS=%llu LAYER_ACQ=%llu DUP=%llu ACTIVE=%u\n",
            (unsigned long long)B.cache.trampOutHits,
            (unsigned long long)B.cache.cycloneLayerAcquires,
            (unsigned long long)B.cache.combinedDupAcquires,
            B.liveActiveAfter ? 1u : 0u);
    auto dlt = LivePath_ComputeDelta(A.s, B.s);
    fprintf(stdout, "VS_A ");
    LivePath_EmitDelta(stdout, dlt);
    const double floor = 0.095;
    const double promo = floor * 1.03;
    const bool ok = A.s.decodeTps >= 0 && B.s.decodeTps > 0;
    const bool parity = A.response == B.response && A.lastTok == B.lastTok;
    const bool teardown = !A.liveActiveAfter && !B.liveActiveAfter;
    const bool noLayer = B.cache.cycloneLayerAcquires == 0;
    const bool trampHit = B.cache.trampOutHits > 0;
    const bool bytesOk = B.s.streamBytesPerToken <= A.s.streamBytesPerToken * 1.001 + 1.0;
    const bool fallback0 = B.s.fallbackCount == 0;
    const bool promoOk = B.s.decodeTps + 1e-12 >= promo;
    const bool beatA = B.s.decodeTps > A.s.decodeTps;
    const bool pass = ok && parity && teardown && noLayer && trampHit && bytesOk &&
                      fallback0 && promoOk;
    printf("BASE_TPS=%.3f OPT_TPS=%.3f PROMO_FLOOR=%.5f\n",
           A.s.decodeTps, B.s.decodeTps, promo);
    printf("OUTPUT_PARITY=%d ACTIVE0=%d LAYER_ACQ0=%d TRAMP_HITS_OK=%d\n",
           parity ? 1 : 0, teardown ? 1 : 0, noLayer ? 1 : 0, trampHit ? 1 : 0);
    printf("PROMO_OK=%d BEAT_LEGACY=%d BYTES_OK=%d\n",
           promoOk ? 1 : 0, beatA ? 1 : 0, bytesOk ? 1 : 0);
    printf("K2_TRAMPOLINE_FULL_DEPTH_OPT_001=%s\n", pass ? "PASS" : "FAIL");
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\K2_TRAMPOLINE_FULL_DEPTH_OPT_001", nullptr);
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_TRAMPOLINE_FULL_DEPTH_OPT_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "BASE_TPS=%.3f OPT_TPS=%.3f PROMO_FLOOR=%.5f BEAT=%d\n",
                A.s.decodeTps, B.s.decodeTps, promo, beatA ? 1 : 0);
        fprintf(f, "parity=%d teardown=%d noLayer=%d tramp=%d bytes=%d fb=%d\n",
                parity, teardown, noLayer, trampHit, bytesOk, fallback0);
        fprintf(f, "K2_TRAMPOLINE_FULL_DEPTH_OPT_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
