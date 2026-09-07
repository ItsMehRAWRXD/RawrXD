// deep2_k2_live_gpu_stream_e2e_cert.cpp — K2_LIVE_GPU_STREAM_E2E_001
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
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
    uint64_t streamBytes = 0, copyOps = 0, copyBytes = 0;
    uint64_t overlapUs = 0, overlapEv = 0;
    int32_t genId = -1;
    std::string text;
    K2LivePolicyDecision pol{};
    bool activeAfter = false;
    uint64_t uploadFail = 0;
};

static RunOut RunOnce(Deep2Engine& e, const char* prompt, uint32_t depth,
                      uint32_t tokens, const char* policyTag) {
    RunOut o{};
#ifdef _WIN32
    _putenv_s("DEEP2_LIVE_POLICY", policyTag);
    _putenv_s("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
    if (policyTag && _stricmp(policyTag, "AUTO") == 0) {
        _putenv_s("DEEP2_LIVE_PATH", "");
        _putenv_s("DEEP2_LIVE_MECH", "");
        // Independent request: do not inherit prior sticky arm.
        K2LivePolicy_ClearSticky();
    }
#endif
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    K2GpuStreamCopy_Reset();
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = tokens; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.runK2NativeStreamPartial(kc);
    o.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    o.ok = r.ok; o.genId = r.generatedTokenId; o.text = r.generatedText;
    o.streamBytes = r.streamBytesRead;
    o.tps = (r.ok && tokens && o.wallMs > 0) ? (1000.0 * tokens / o.wallMs) : 0.0;
    o.pol = K2LivePolicy_Last();
    o.activeAfter = LivePath_Active();
    auto g = GpuTransfer_Snapshot();
    o.copyOps = g.copyOps; o.copyBytes = g.copyBytes;
    o.overlapUs = g.overlapUs; o.overlapEv = g.overlapEvents;
    o.uploadFail = K2GpuStreamCopy_FailOps();
    return o;
}

static bool ArmIsOff(const K2LivePolicyDecision& d) {
    return d.mode == K2LivePolicyMode::Off;
}
static bool ArmIsLiveCache(const K2LivePolicyDecision& d) {
    return d.mode == K2LivePolicyMode::TrampolineOutput ||
           d.mode == K2LivePolicyMode::LayerCycloneElastic;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "4");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "1");
    _putenv_s("DEEP2_WEIGHT_OVERLAP", "1");
    _putenv_s("DEEP2_K2_GPU_STREAM_COPY", "1");
    _putenv_s("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    _putenv_s("DEEP2_LIVE_ALLOW_LAYER_CACHE", "0");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_LIVE_GPU_STREAM_E2E_001", nullptr);
    printf("K2_LIVE_GPU_STREAM_E2E_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_LIVE_GPU_STREAM_E2E_001=SKIP\n"); return 0;
    }
    static const char* kPrompt =
        "Write one short paragraph on local decode tok/s.";
    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_LIVE_GPU_STREAM_E2E_001=FAIL open\n"); return 2;
    }

    printf("\n--- AUTO below crossover (d=2 t=2) + GPU stream ---\n");
    RunOut autoLo = RunOnce(eng, kPrompt, 2, 2, "AUTO");
    K2LivePolicy_Emit(stdout, autoLo.pol);
    K2GpuStreamCopy_Emit(stdout);
    printf("GPU_COPY_OPS=%llu OVERLAP_EV=%llu ACTIVE_AFTER=%u\n",
           (unsigned long long)autoLo.copyOps,
           (unsigned long long)autoLo.overlapEv,
           autoLo.activeAfter ? 1u : 0u);

    printf("\n--- AUTO above crossover (d=4 t=2) + GPU stream ---\n");
    RunOut autoHi = RunOnce(eng, kPrompt, 4, 2, "AUTO");
    K2LivePolicy_Emit(stdout, autoHi.pol);
    K2GpuStreamCopy_Emit(stdout);
    GpuTransfer_Emit(stdout);

    printf("\n--- MANUAL champion TRAMPOLINE (d=4 t=2) + GPU stream ---\n");
    RunOut manHi = RunOnce(eng, kPrompt, 4, 2, "TRAMPOLINE");
    K2LivePolicy_Emit(stdout, manHi.pol);

    const bool autoActive =
        autoLo.pol.autoSelected == 1 && autoHi.pol.autoSelected == 1;
    const bool noManual =
        autoLo.pol.manualOverride == 0 && autoHi.pol.manualOverride == 0;
    const bool matchLo = ArmIsOff(autoLo.pol) && autoLo.pol.reuseSteps < 8;
    const bool matchHi = ArmIsLiveCache(autoHi.pol) && autoHi.pol.reuseSteps >= 8;
    const bool teardown = !autoLo.activeAfter && !autoHi.activeAfter;
    const bool switchesOk =
        autoLo.pol.switches <= 1 && autoHi.pol.switches <= 1;
    const bool gpuMoved = autoHi.copyOps > 0 && autoHi.copyBytes > 0 &&
                          autoLo.copyOps > 0;
    const bool gpuOverlap = autoHi.overlapEv > 0;
    const bool laneOk = autoHi.uploadFail == 0 && autoLo.uploadFail == 0;
    const bool bound = K2GpuStreamCopy_Wanted() && eng.getVulkanComputeSlot(0);
    const bool parity = manHi.ok && autoHi.ok &&
        autoHi.genId == manHi.genId && autoHi.text == manHi.text;
    const bool tpsOk = manHi.tps <= 0 || autoHi.tps >= 0.90 * manHi.tps;
    const bool fallback = !autoLo.ok || !autoHi.ok || !manHi.ok;

    printf("\nAUTO_POLICY_ACTIVE=%u\nMANUAL_ARM_FORCING=%u\n",
           autoActive ? 1u : 0u, noManual ? 0u : 1u);
    printf("POLICY_MATCH_EXPECTED=%u\n", (matchLo && matchHi) ? 1u : 0u);
    printf("GPU_STREAM_COPY_ACTIVE=%u\n", gpuMoved ? 1u : 0u);
    printf("GPU_COPY_OVERLAP_ACTIVE=%u\n", gpuOverlap ? 1u : 0u);
    printf("OUTPUT_PARITY=%u\nFALLBACK=%u\nACTIVE_AFTER_TEARDOWN=%u\n",
           parity ? 1u : 0u, fallback ? 1u : 0u, teardown ? 0u : 1u);
    printf("TPS_AUTO=%.3f TPS_MANUAL=%.3f\n", autoHi.tps, manHi.tps);

    const bool pass = autoActive && noManual && matchLo && matchHi &&
                      teardown && switchesOk && !fallback && bound &&
                      gpuMoved && gpuOverlap && laneOk && parity && tpsOk;
    printf("K2_LIVE_GPU_STREAM_E2E_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_LIVE_GPU_STREAM_E2E_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f,
                "auto=%d noManual=%d matchLo=%d matchHi=%d gpu=%d ov=%d "
                "parity=%d teardown=%d tpsOk=%d\n",
                autoActive, noManual, matchLo, matchHi, gpuMoved, gpuOverlap,
                parity, teardown, tpsOk);
        fprintf(f, "GPU_COPY_OPS_HI=%llu OVERLAP_EV_HI=%llu\n",
                (unsigned long long)autoHi.copyOps,
                (unsigned long long)autoHi.overlapEv);
        fprintf(f, "K2_LIVE_GPU_STREAM_E2E_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
