// deep2_k2_full_depth_effectiveness_cert.cpp — K2_FULL_DEPTH_EFFECTIVENESS_001
// A0 baseline | B2 trampoline | Bbest cyclone+elastic (best multi-mech from bounds)
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "GpuTransferCounters.hpp"
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

struct ArmDef { const char* id; const char* live; const char* mech; };
struct ArmOut {
    LivePathEffectSnap s;
    std::string text;
    int32_t lastTok = -1;
    bool liveActiveAfter = true;
    uint64_t gpuCopyBytes = 0, gpuCopyOps = 0, gpuOverlapUs = 0;
};

static ArmOut RunArm(const ArmDef& d, const char* dir, uint32_t nTok,
                     uint32_t depth, const char* prompt) {
    ArmOut o;
    o.s.tokens = nTok; o.s.layerDepth = depth;
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_LIVE_POLICY", "MANUAL");
    _putenv_s("DEEP2_LIVE_POLICY", "MANUAL");
    SetEnvironmentVariableA("DEEP2_LIVE_PATH", d.live);
    _putenv_s("DEEP2_LIVE_PATH", d.live);
    SetEnvironmentVariableA("DEEP2_LIVE_MECH", d.mech);
    _putenv_s("DEEP2_LIVE_MECH", d.mech);
    const bool on = d.live[0] != '0';
    SetEnvironmentVariableA("DEEP2_LIVE_FUSED", on ? "1" : "0");
    _putenv_s("DEEP2_LIVE_FUSED", on ? "1" : "0");
#endif
    LivePath_SetEnhancementsEnabled(d.live[0] != '0');
    LivePath_SetFusedEnabled(d.live[0] != '0');
    LivePath_ApplyMechEnv();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
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
    o.s.residentWeightPeak = r.peakResidencyBytes;
    o.s.streamBytesRead = r.streamBytesRead;
    o.s.streamBytesToGpu = r.streamBytesToGpu;
    o.s.streamBytesRecon = r.streamBytesReconstructed;
    o.s.streamBytesPerToken = r.streamBytesPerToken;
    o.s.cacheHits = r.streamCacheHits;
    o.s.cacheMisses = r.streamCacheMisses;
    o.s.fallbackCount = e->vulkanGemvFallbackCount();
    LivePath_FillEffectFromCounters(o.s);
    o.s.enhancements = (d.live[0] != '0') ? 1u : 0u;
    o.text = r.generatedText;
    o.lastTok = r.generatedTokenId;
    o.liveActiveAfter = LivePath_Active();
    auto g = GpuTransfer_Snapshot();
    o.gpuCopyBytes = g.copyBytes; o.gpuCopyOps = g.copyOps;
    o.gpuOverlapUs = g.overlapUs;
    if (!r.ok) o.s.decodeTps = 0;
    return o;
}

static void EmitArm(FILE* f, const char* id, const ArmOut& o) {
    LivePath_EmitEffect(f, id, o.s);
    fprintf(f, "GPU_COPY_BYTES=%llu\nGPU_COPY_OPS=%llu\nGPU_COPY_OVERLAP_US=%llu\n",
            (unsigned long long)o.gpuCopyBytes, (unsigned long long)o.gpuCopyOps,
            (unsigned long long)o.gpuOverlapUs);
    fprintf(f, "OUTPUT_TEXT=%s\nOUTPUT_LAST_TOK=%d\nLIVE_PATH_ACTIVE=%u\n",
            o.text.c_str(), o.lastTok, o.liveActiveAfter ? 1u : 0u);
    fflush(f);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    if (!fs::is_directory(dir)) {
        printf("SKIP_NO_MODEL\nK2_FULL_DEPTH_EFFECTIVENESS_001=SKIP\n");
        return 0;
    }
    uint32_t nTok = 2, depth = 61;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS"))
        nTok = (uint32_t)std::max(1, atoi(t));
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    // Bbest = cyclone+elastic (best multi-mech from ib_matrix_fixed)
    static const ArmDef kArms[] = {
        {"A0", "0", "none"},
        {"B2", "1", "trampoline"},
        {"Bbest", "1", "cyclone,elastic"},
    };
    printf("K2_FULL_DEPTH_EFFECTIVENESS_001\nMODEL=%s TOKENS=%u DEPTH=%u\n",
           dir, nTok, depth);
    printf("BBEST_MECH=cyclone,elastic (from LIVE_PATH_INTERACTION_BOUNDS_001)\n");
    ArmOut arms[3];
    for (int i = 0; i < 3; ++i) {
        arms[i] = RunArm(kArms[i], dir, nTok, depth, kPrompt);
        EmitArm(stdout, kArms[i].id, arms[i]);
        if (i > 0) {
            auto d = LivePath_ComputeDelta(arms[0].s, arms[i].s);
            fprintf(stdout, "VS_A0 %s ", kArms[i].id);
            LivePath_EmitDelta(stdout, d);
        }
    }
    const bool ok = arms[0].s.decodeTps >= 0 && arms[1].s.decodeTps > 0 &&
                    arms[2].s.decodeTps > 0;
    const bool parity = arms[0].text == arms[1].text &&
                        arms[1].text == arms[2].text &&
                        arms[0].lastTok == arms[1].lastTok &&
                        arms[1].lastTok == arms[2].lastTok;
    const bool teardown = !arms[1].liveActiveAfter && !arms[2].liveActiveAfter;
    const bool b2Win = arms[1].s.decodeTps > arms[0].s.decodeTps;
    const bool bestBeatsA0 = arms[2].s.decodeTps > arms[0].s.decodeTps;
    const bool bestBeatsB2 = arms[2].s.decodeTps > arms[1].s.decodeTps;
    const bool b2BytesOk = arms[1].s.streamBytesRead <= arms[0].s.streamBytesRead;
    const char* champ = "A0";
    double bestTps = arms[0].s.decodeTps;
    if (arms[1].s.decodeTps > bestTps) { bestTps = arms[1].s.decodeTps; champ = "B2"; }
    if (arms[2].s.decodeTps > bestTps) { bestTps = arms[2].s.decodeTps; champ = "Bbest"; }
    const bool pass = ok && teardown && parity && b2Win && bestBeatsA0 && b2BytesOk;
    printf("OUTPUT_PARITY_B2_Bbest=%d TEARDOWN_ACTIVE0=%d\n", parity ? 1 : 0,
           teardown ? 1 : 0);
    printf("B2_BEATS_A0=%d BBEST_BEATS_A0=%d BBEST_BEATS_B2=%d\n",
           b2Win ? 1 : 0, bestBeatsA0 ? 1 : 0, bestBeatsB2 ? 1 : 0);
    printf("CHAMPION=%s CHAMPION_TPS=%.3f\n", champ, bestTps);
    printf("K2_FULL_DEPTH_EFFECTIVENESS_001=%s\n", pass ? "PASS" : "FAIL");
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
