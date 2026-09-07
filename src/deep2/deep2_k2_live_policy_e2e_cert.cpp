// deep2_k2_live_policy_e2e_cert.cpp — K2_LIVE_POLICY_E2E_001
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
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

struct RunOut {
    bool ok = false;
    double tps = 0, wallMs = 0;
    uint64_t bytes = 0;
    int32_t genId = -1;
    std::string text;
    K2LivePolicyDecision pol{};
    bool activeAfter = false;
};

#ifdef _WIN32
static bool EqPolicyIsAuto(const char* p) {
    return p && _stricmp(p, "AUTO") == 0;
}
#else
static bool EqPolicyIsAuto(const char* p) {
    return p && strcasecmp(p, "AUTO") == 0;
}
#endif

static RunOut RunOnce(Deep2Engine& e, const char* prompt, uint32_t depth,
                      uint32_t tokens, const char* policyTag) {
    RunOut o{};
#ifdef _WIN32
    _putenv_s("DEEP2_LIVE_POLICY", policyTag);
    _putenv_s("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
    if (EqPolicyIsAuto(policyTag)) {
        _putenv_s("DEEP2_LIVE_PATH", "");
        _putenv_s("DEEP2_LIVE_MECH", "");
    }
#endif
    StreamTransfer_Reset();
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = tokens; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.runK2NativeStreamPartial(kc);
    o.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    o.ok = r.ok; o.genId = r.generatedTokenId; o.text = r.generatedText;
    o.bytes = r.streamBytesRead;
    o.tps = (r.ok && tokens && o.wallMs > 0) ? (1000.0 * tokens / o.wallMs) : 0.0;
    o.pol = K2LivePolicy_Last();
    o.activeAfter = LivePath_Active();
    return o;
}

static bool ArmIsOff(const K2LivePolicyDecision& d) {
    return d.mode == K2LivePolicyMode::Off && d.arm && std::strcmp(d.arm, "OFF") == 0;
}
static bool ArmIsTrampoline(const K2LivePolicyDecision& d) {
    return d.mode == K2LivePolicyMode::TrampolineOutput && d.arm &&
           std::strcmp(d.arm, "TRAMPOLINE_OUTPUT_CACHE") == 0;
}
static bool ArmIsPromo(const K2LivePolicyDecision& d) {
    return d.mode == K2LivePolicyMode::TrampolineOutput && d.arm &&
           std::strcmp(d.arm, "FULL_DEPTH_PROMO") == 0 && d.layerVeto == 1;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    _putenv_s("DEEP2_LIVE_FUSED", "0");
    _putenv_s("DEEP2_LIVE_ALLOW_LAYER_CACHE", "0");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_LIVE_POLICY_E2E_001", nullptr);
    printf("K2_LIVE_POLICY_E2E_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_LIVE_POLICY_E2E_001=SKIP\n"); return 0;
    }
    static const char* kPrompt =
        "Write one short paragraph on local decode tok/s.";
    Deep2Engine* eng = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng->initialize(cfg) || !eng->openK2ShardDirectory(dir)) {
        printf("K2_LIVE_POLICY_E2E_001=FAIL open\n"); return 2;
    }

    printf("\n--- AUTO below crossover (d=2 t=2 steps=4) ---\n");
    K2LivePolicy_ClearSticky();
    RunOut autoLo = RunOnce(*eng, kPrompt, 2, 2, "AUTO");
    K2LivePolicy_Emit(stdout, autoLo.pol);
    printf("ACTIVE_AFTER_TEARDOWN=%u SELECTED=%s\n",
           autoLo.activeAfter ? 1u : 0u,
           autoLo.pol.arm ? autoLo.pol.arm : "?");

    printf("\n--- AUTO above crossover (d=4 t=2 steps=8) ---\n");
    K2LivePolicy_ClearSticky();
    RunOut autoHi = RunOnce(*eng, kPrompt, 4, 2, "AUTO");
    K2LivePolicy_Emit(stdout, autoHi.pol);
    printf("ACTIVE_AFTER_TEARDOWN=%u SELECTED=%s\n",
           autoHi.activeAfter ? 1u : 0u,
           autoHi.pol.arm ? autoHi.pol.arm : "?");

    printf("\n--- MANUAL champion CACHE_FULL/TRAMPOLINE (d=4 t=2) ---\n");
    K2LivePolicy_ClearSticky();
    RunOut manHi = RunOnce(*eng, kPrompt, 4, 2, "TRAMPOLINE");
    K2LivePolicy_Emit(stdout, manHi.pol);

    printf("\n--- AUTO full-depth promo (d=61 t=2) ---\n");
    K2LivePolicy_ClearSticky();
    RunOut autoFull = RunOnce(*eng, kPrompt, 61, 2, "AUTO");
    K2LivePolicy_Emit(stdout, autoFull.pol);
    printf("ACTIVE_AFTER_TEARDOWN=%u SELECTED=%s\n",
           autoFull.activeAfter ? 1u : 0u,
           autoFull.pol.arm ? autoFull.pol.arm : "?");

    const bool autoActive =
        autoLo.pol.autoSelected == 1 && autoHi.pol.autoSelected == 1 &&
        autoFull.pol.autoSelected == 1;
    const bool noManualForce =
        autoLo.pol.manualOverride == 0 && autoHi.pol.manualOverride == 0 &&
        autoFull.pol.manualOverride == 0;
    const bool matchLo = ArmIsOff(autoLo.pol) && autoLo.pol.reuseSteps < 8;
    const bool matchHi = ArmIsTrampoline(autoHi.pol) && autoHi.pol.reuseSteps >= 8;
    const bool matchFull = ArmIsPromo(autoFull.pol);
    const bool teardownOk =
        !autoLo.activeAfter && !autoHi.activeAfter && !autoFull.activeAfter;
    const bool switchesOk =
        autoLo.pol.switches <= 1 && autoHi.pol.switches <= 1 &&
        autoFull.pol.switches <= 1;
    const bool parity = manHi.ok && autoHi.ok &&
        autoHi.genId == manHi.genId && autoHi.text == manHi.text;
    const bool tpsOk = manHi.tps <= 0 || autoHi.tps >= 0.97 * manHi.tps;
    const bool bytesOk = manHi.bytes == 0 ||
        autoHi.bytes <= (uint64_t)((double)manHi.bytes * 1.03 + 0.5);
    const bool fallback = !autoLo.ok || !autoHi.ok || !manHi.ok || !autoFull.ok;

    printf("\nAUTO_POLICY_ACTIVE=%u\nMANUAL_ARM_FORCING=%u\n",
           autoActive ? 1u : 0u, noManualForce ? 0u : 1u);
    printf("POLICY_MATCH_EXPECTED=%u FULL_PROMO=%u\n",
           (matchLo && matchHi) ? 1u : 0u, matchFull ? 1u : 0u);
    printf("OUTPUT_PARITY=%u\n", parity ? 1u : 0u);
    printf("FALLBACK=%u\n", fallback ? 1u : 0u);
    printf("ACTIVE_AFTER_TEARDOWN=%u\n", teardownOk ? 0u : 1u);
    printf("POLICY_SWITCHES_PER_REQUEST lo=%u hi=%u full=%u\n",
           autoLo.pol.switches, autoHi.pol.switches, autoFull.pol.switches);
    printf("TPS_AUTO=%.3f TPS_MANUAL=%.3f BYTES_AUTO=%llu BYTES_MANUAL=%llu\n",
           autoHi.tps, manHi.tps,
           (unsigned long long)autoHi.bytes, (unsigned long long)manHi.bytes);

    const bool pass = autoActive && noManualForce && matchLo && matchHi &&
                      matchFull && teardownOk && switchesOk && !fallback &&
                      parity && tpsOk && bytesOk;
    printf("K2_LIVE_POLICY_E2E_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_LIVE_POLICY_E2E_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f,
                "autoActive=%d noManual=%d matchLo=%d matchHi=%d matchFull=%d "
                "parity=%d teardown=%d switches=%d tpsOk=%d bytesOk=%d fallback=%d\n",
                autoActive, noManualForce, matchLo, matchHi, matchFull, parity,
                teardownOk, switchesOk, tpsOk, bytesOk, fallback);
        fprintf(f, "K2_LIVE_POLICY_E2E_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
