// K2FullDepthCombined_Arm.cpp — A0 / Bbest / C002 arm runner
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "FusedLiveController.hpp"
#include "GpuTransferCounters.hpp"
#include "K2LivePathTensorCache.hpp"
#include "LivePathEffect.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include <chrono>
#include <cstdlib>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

struct CombinedArmDef {
    const char* id;
    const char* live;   // "0" | "1"
    const char* mech;
    const char* fused;  // "0" | "1"
};

struct CombinedArmOut {
    LivePathEffectSnap s;
    K2LiveCacheStats cache{};
    uint64_t postWarmAllocs = 0;
    std::string text;
    int32_t lastTok = -1;
    bool liveActiveAfter = true;
    FusedCounters fused{};
};

CombinedArmOut K2_CombinedPolicy_RunArm(const CombinedArmDef& d, const char* dir,
                                        uint32_t nTok, uint32_t depth,
                                        const char* prompt) {
    CombinedArmOut o;
    o.s.tokens = nTok;
    o.s.layerDepth = depth;
    const bool on = d.live[0] != '0';
    const bool fused = d.fused[0] == '1';
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_LIVE_POLICY", "MANUAL");
    _putenv_s("DEEP2_LIVE_POLICY", "MANUAL");
    SetEnvironmentVariableA("DEEP2_LIVE_PATH", d.live);
    _putenv_s("DEEP2_LIVE_PATH", d.live);
    SetEnvironmentVariableA("DEEP2_LIVE_MECH", d.mech);
    _putenv_s("DEEP2_LIVE_MECH", d.mech);
    SetEnvironmentVariableA("DEEP2_LIVE_FUSED", d.fused);
    _putenv_s("DEEP2_LIVE_FUSED", d.fused);
#endif
    LivePath_SetEnhancementsEnabled(on);
    LivePath_SetFusedEnabled(fused);
    LivePath_ApplyMechEnv();
    StreamTransfer_Reset();
    StreamPathTiming_Reset();
    GpuTransfer_Reset();
    Fused_Reset();
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
    o.s.streamBytesToGpu = r.streamBytesToGpu;
    o.s.streamBytesPerToken = r.streamBytesPerToken;
    o.s.cacheHits = r.streamCacheHits;
    o.s.cacheMisses = r.streamCacheMisses;
    o.s.fallbackCount = e->vulkanGemvFallbackCount();
    LivePath_FillEffectFromCounters(o.s);
    o.s.enhancements = on ? 1u : 0u;
    o.cache = K2LiveCache_Snapshot();
    o.postWarmAllocs = StreamTransfer_PostWarmAllocs();
    o.text = r.generatedText;
    o.lastTok = r.generatedTokenId;
    o.liveActiveAfter = LivePath_Active();
    o.fused = Fused_Counters();
    if (!r.ok) o.s.decodeTps = 0;
    // Intentionally leak engine: ~Deep2Engine heap-corrupts under multi-arm certs.
    // Process ends via _exit after all arms.
    return o;
}

} // namespace Deep2
