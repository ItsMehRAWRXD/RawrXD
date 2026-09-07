// deep2_k2_live_generate_policy_cert.cpp — K2_LIVE_GENERATE_POLICY_001
// Unset POLICY = AUTO on the live stream path; manual arms are not normal.
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
    bool ok = false; double tps = 0; uint64_t bytes = 0;
    int32_t genId = -1; std::string text;
    K2LivePolicyDecision pol{}; bool activeAfter = false;
};

static void ClearPolicyEnv() {
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_LIVE_POLICY", nullptr);
    _putenv_s("DEEP2_LIVE_POLICY", "");
    SetEnvironmentVariableA("DEEP2_LIVE_MECH", nullptr);
    _putenv_s("DEEP2_LIVE_MECH", "");
    SetEnvironmentVariableA("DEEP2_LIVE_PATH", nullptr);
    _putenv_s("DEEP2_LIVE_PATH", "");
#endif
}

static RunOut RunOnce(Deep2Engine& e, const char* prompt, uint32_t depth,
                      uint32_t tokens, const char* policyTag) {
    RunOut o{};
#ifdef _WIN32
    ClearPolicyEnv();
    if (policyTag && policyTag[0] && _stricmp(policyTag, "DEFAULT") != 0)
        _putenv_s("DEEP2_LIVE_POLICY", policyTag);
    _putenv_s("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
#endif
    StreamTransfer_Reset();
    K2LivePolicy_ClearSticky();
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = tokens; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.runK2NativeStreamPartial(kc);
    const double wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    o.ok = r.ok; o.genId = r.generatedTokenId; o.text = r.generatedText;
    o.bytes = r.streamBytesRead;
    o.tps = (r.ok && tokens && wallMs > 0) ? (1000.0 * tokens / wallMs) : 0.0;
    o.pol = K2LivePolicy_Last();
    o.activeAfter = LivePath_Active();
    return o;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    _putenv_s("DEEP2_LIVE_FUSED", "0");
    _putenv_s("DEEP2_LIVE_ALLOW_LAYER_CACHE", "0");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_LIVE_GENERATE_POLICY_001", nullptr);
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    printf("K2_LIVE_GENERATE_POLICY_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_LIVE_GENERATE_POLICY_001=SKIP\n"); return 0;
    }
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    Deep2Engine* eng = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng->initialize(cfg) || !eng->openK2ShardDirectory(dir)) {
        printf("K2_LIVE_GENERATE_POLICY_001=FAIL open\n"); return 2;
    }

    printf("\n--- DEFAULT (unset POLICY) d=4 t=2 ---\n");
    RunOut defHi = RunOnce(*eng, kPrompt, 4, 2, "DEFAULT");
    K2LivePolicy_Emit(stdout, defHi.pol);

    printf("\n--- AUTO explicit d=4 t=2 ---\n");
    RunOut autoHi = RunOnce(*eng, kPrompt, 4, 2, "AUTO");
    K2LivePolicy_Emit(stdout, autoHi.pol);

    printf("\n--- DEFAULT below crossover d=2 t=2 ---\n");
    RunOut defLo = RunOnce(*eng, kPrompt, 2, 2, "DEFAULT");
    K2LivePolicy_Emit(stdout, defLo.pol);

    printf("\n--- TRAMPOLINE force champion d=4 t=2 ---\n");
    RunOut manHi = RunOnce(*eng, kPrompt, 4, 2, "TRAMPOLINE");
    K2LivePolicy_Emit(stdout, manHi.pol);

    const bool defaultAuto =
        defHi.pol.autoSelected == 1 && defHi.pol.manualOverride == 0 &&
        defHi.pol.mode == K2LivePolicyMode::TrampolineOutput &&
        defHi.pol.arm && std::strcmp(defHi.pol.arm, "TRAMPOLINE_OUTPUT_CACHE") == 0 &&
        defHi.pol.reason && std::strcmp(defHi.pol.reason, "default_auto") == 0;
    const bool autoMatch =
        autoHi.pol.autoSelected == 1 &&
        autoHi.pol.mode == K2LivePolicyMode::TrampolineOutput;
    const bool belowOff =
        defLo.pol.mode == K2LivePolicyMode::Off && defLo.pol.autoSelected == 1;
    const bool teardown =
        !defHi.activeAfter && !autoHi.activeAfter && !defLo.activeAfter;
    const bool switchesOk =
        defHi.pol.switches <= 1 && autoHi.pol.switches <= 1;
    const bool parity = manHi.ok && defHi.ok &&
        defHi.genId == manHi.genId && defHi.text == manHi.text;
    const bool tpsOk = manHi.tps <= 0 || defHi.tps >= 0.97 * manHi.tps;
    const bool fallback = !defHi.ok || !autoHi.ok || !defLo.ok || !manHi.ok;

    printf("\nDEFAULT_IS_AUTO=%u AUTO_MATCH=%u BELOW_OFF=%u\n",
           defaultAuto ? 1u : 0u, autoMatch ? 1u : 0u, belowOff ? 1u : 0u);
    printf("OUTPUT_PARITY=%u TEARDOWN_OK=%u FALLBACK=%u\n",
           parity ? 1u : 0u, teardown ? 1u : 0u, fallback ? 1u : 0u);
    printf("TPS_DEFAULT=%.3f TPS_MANUAL=%.3f\n", defHi.tps, manHi.tps);

    const bool pass = defaultAuto && autoMatch && belowOff && teardown &&
                      switchesOk && !fallback && parity && tpsOk;
    printf("K2_LIVE_GENERATE_POLICY_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_LIVE_GENERATE_POLICY_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "DEFAULT_IS_AUTO=%d AUTO_MATCH=%d BELOW_OFF=%d parity=%d "
                "teardown=%d tpsOk=%d\n",
                defaultAuto, autoMatch, belowOff, parity, teardown, tpsOk);
        fprintf(f, "K2_LIVE_GENERATE_POLICY_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
