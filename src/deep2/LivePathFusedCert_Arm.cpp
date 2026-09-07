// LivePathFusedCert_Arm.cpp — A/B/C arm runner for fused-control cert
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "FusedLiveController.hpp"
#include "LivePathEffect.hpp"
#include "StreamTransferCounters.hpp"
#include "WarmupScheduler.hpp"
#include <chrono>
#include <cstdlib>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

enum FusedArm : int { FUSED_ARM_A = 0, FUSED_ARM_B = 1, FUSED_ARM_C = 2 };

LivePathEffectSnap LivePath_FusedCertRunArm(int arm, const char* dir, uint32_t nTok,
                                            uint32_t depth, const char* prompt) {
    LivePathEffectSnap s;
    s.tokens = nTok;
    s.layerDepth = depth;
    const bool enh = (arm != FUSED_ARM_A);
    const bool fused = (arm == FUSED_ARM_C);
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_LIVE_POLICY", "MANUAL");
    _putenv_s("DEEP2_LIVE_POLICY", "MANUAL");
    SetEnvironmentVariableA("DEEP2_LIVE_PATH", enh ? "1" : "0");
    _putenv_s("DEEP2_LIVE_PATH", enh ? "1" : "0");
    _putenv_s("DEEP2_LIVE_FUSED", fused ? "1" : "0");
#endif
    LivePath_SetEnhancementsEnabled(enh);
    LivePath_SetFusedEnabled(fused);
    StreamTransfer_Reset();
    Fused_Reset();
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
    s.enhancements = enh ? 1u : 0u;
    if (!r.ok) s.decodeTps = 0;
    return s;
}

} // namespace Deep2
