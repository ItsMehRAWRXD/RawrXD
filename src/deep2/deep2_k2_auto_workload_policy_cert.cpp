// deep2_k2_auto_workload_policy_cert.cpp — K2_AUTO_WORKLOAD_POLICY_001
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "StreamTransferCounters.hpp"
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

struct Arm {
    double tps = 0, wallMs = 0;
    uint64_t streamBytes = 0, cachePeak = 0, fallback = 0;
    std::string text; int32_t lastTok = -1;
    bool active = true, ok = false;
    K2LivePolicyDecision pol{};
};

static Arm Run(const char* policy, const char* mech, const char* dir,
               uint32_t nTok, uint32_t depth, const char* prompt) {
    Arm a;
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_LIVE_POLICY", policy);
    _putenv_s("DEEP2_LIVE_POLICY", policy);
    SetEnvironmentVariableA("DEEP2_LIVE_ALLOW_LAYER_CACHE", "0");
    _putenv_s("DEEP2_LIVE_ALLOW_LAYER_CACHE", "0");
    SetEnvironmentVariableA("DEEP2_LIVE_FUSED", "0");
    _putenv_s("DEEP2_LIVE_FUSED", "0");
    if (mech && mech[0]) {
        SetEnvironmentVariableA("DEEP2_LIVE_MECH", mech);
        _putenv_s("DEEP2_LIVE_MECH", mech);
        SetEnvironmentVariableA("DEEP2_LIVE_PATH", "1");
        _putenv_s("DEEP2_LIVE_PATH", "1");
        LivePath_SetEnhancementsEnabled(true);
        LivePath_ApplyMechEnv();
    }
#endif
    if (strcmp(policy, "AUTO") == 0)
        a.pol = K2LivePolicy_Apply(depth, nTok);
    StreamTransfer_Reset();
    auto* e = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64; cfg.numKVHeads = 1;
    cfg.vocabSize = 163840; cfg.useMLA = true; cfg.maxSeqLen = 128;
    cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 8;
    if (!e->initialize(cfg) || !e->openK2ShardDirectory(dir)) return a;
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = nTok; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e->runK2NativeStreamPartial(kc);
    a.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    a.tps = (r.ok && a.wallMs > 0) ? ((double)nTok * 1000.0 / a.wallMs) : 0.0;
    a.streamBytes = r.streamBytesRead;
    a.cachePeak = K2LiveCache_Snapshot().bytesPeak;
    a.fallback = e->vulkanGemvFallbackCount();
    a.text = r.generatedText; a.lastTok = r.generatedTokenId;
    a.active = LivePath_Active(); a.ok = r.ok;
    if (strcmp(policy, "AUTO") != 0)
        a.pol = K2LivePolicy_Decide(depth, nTok);
    return a;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_AUTO_WORKLOAD_POLICY_001", nullptr);
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    if (!fs::is_directory(dir)) {
        printf("SKIP\nK2_AUTO_WORKLOAD_POLICY_001=SKIP\n"); return 0;
    }
    uint32_t nTok = 2, depth = 61;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS")) nTok = (uint32_t)std::max(1, atoi(t));
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    printf("K2_AUTO_WORKLOAD_POLICY_001 TOKENS=%u DEPTH=%u\n", nTok, depth);
    auto d61 = K2LivePolicy_Decide(61, nTok);
    K2LivePolicy_Emit(stdout, d61);
    const bool classOk = d61.mode == K2LivePolicyMode::TrampolineOutput &&
                         d61.layerVeto == 1 &&
                         d61.arm && std::strcmp(d61.arm, "FULL_DEPTH_PROMO") == 0;

    Arm champ = Run("MANUAL", "trampoline", dir, nTok, depth, kPrompt);
    Arm autoA = Run("AUTO", "", dir, nTok, depth, kPrompt);
    K2LivePolicy_Emit(stdout, autoA.pol);
    const bool autoSel = autoA.pol.autoSelected == 1 && autoA.pol.manualOverride == 0;
    const bool armMatch = autoA.pol.mode == K2LivePolicyMode::TrampolineOutput &&
                          autoA.pol.arm &&
                          std::strcmp(autoA.pol.arm, "FULL_DEPTH_PROMO") == 0;
    K2LivePolicy_Apply(depth, nTok);
    const bool mechOk = LivePath_MechOn(LP_MECH_TRAMPOLINE) &&
                        LivePath_MechOn(LP_MECH_CYCLONE) &&
                        LivePath_MechOn(LP_MECH_ELASTIC) &&
                        LivePath_FusedEnabled();
    // 95% floor: AUTO Promo+C002 vs pure-B2; same-mech rebench already
    // proved >=97% (K2_FULL_DEPTH_FUSED_REBENCH_001). Cross-arm noise ~few %.
    const double floorTps = champ.tps * 0.95;
    const bool tpsOk = autoA.ok && champ.ok && autoA.tps + 1e-12 >= floorTps;
    const bool parity = !champ.text.empty() && champ.text == autoA.text &&
                        champ.lastTok == autoA.lastTok;
    const bool pass = classOk && autoSel && armMatch && mechOk && tpsOk && parity &&
                      autoA.fallback == 0 && !autoA.active &&
                      autoA.cachePeak <= K2LivePolicy_CacheBudgetBytes() &&
                      autoA.pol.switches <= 1;
    printf("CHAMP_TPS=%.3f AUTO_TPS=%.3f FLOOR=%.3f\n", champ.tps, autoA.tps, floorTps);
    printf("OUTPUT_PARITY=%d SWITCHES=%u FUSED=%d\n",
           parity ? 1 : 0, autoA.pol.switches, LivePath_FusedEnabled() ? 1 : 0);
    printf("K2_AUTO_WORKLOAD_POLICY_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_AUTO_WORKLOAD_POLICY_001\\GATE_STATUS.txt", "w");
    if (f) {
        K2LivePolicy_Emit(f, autoA.pol);
        fprintf(f, "CHAMP_TPS=%.3f AUTO_TPS=%.3f\n", champ.tps, autoA.tps);
        fprintf(f, "OUTPUT_PARITY=%d\nK2_AUTO_WORKLOAD_POLICY_001=%s\n",
                parity ? 1 : 0, pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
