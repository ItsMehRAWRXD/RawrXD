// deep2_k2_live_policy_crossover_cert.cpp — K2_LIVE_POLICY_CROSSOVER_001
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "K2LivePolicy.hpp"
#include "K2LivePathTensorCache.hpp"
#include "StreamTransferCounters.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <tuple>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

struct Point {
    uint32_t depth = 0, tokens = 0;
    double tpsA = 0, tpsB = 0, wallA = 0, wallB = 0;
    uint64_t readA = 0, readB = 0, hitsB = 0, cachePeakB = 0;
    bool okA = false, okB = false;
};

static Point RunPair(Deep2Engine& eng, const char* prompt,
                     uint32_t depth, uint32_t tokens) {
    Point p{}; p.depth = depth; p.tokens = tokens;
    auto one = [&](bool live) {
        LivePath_SetEnhancementsEnabled(live);
#ifdef _WIN32
        _putenv_s("DEEP2_LIVE_PATH", live ? "1" : "0");
#endif
        StreamTransfer_Reset();
        K2NativeStreamGate::Config kc;
        kc.prompt = prompt; kc.streamTokens = tokens; kc.layerDepth = depth;
        kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
        auto t0 = std::chrono::steady_clock::now();
        auto r = eng.runK2NativeStreamPartial(kc);
        double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        double tps = (r.ok && tokens && ms > 0) ? (1000.0 * tokens / ms) : 0.0;
        return std::make_tuple(r.ok, tps, ms, r.streamBytesRead,
                               K2LiveCache_Snapshot());
    };
    auto [okA, tA, wA, rA, cA] = one(false);
    p.okA = okA; p.tpsA = tA; p.wallA = wA; p.readA = rA;
    auto [okB, tB, wB, rB, cB] = one(true);
    p.okB = okB; p.tpsB = tB; p.wallB = wB; p.readB = rB;
    p.hitsB = cB.hits; p.cachePeakB = cB.bytesPeak;
    printf("POINT d=%u t=%u steps=%llu TPS_A=%.3f TPS_B=%.3f "
           "WALL_A=%.0f WALL_B=%.0f READ_A=%llu READ_B=%llu HITS_B=%llu "
           "CACHE_PEAK_B=%llu WIN=%d\n",
           depth, tokens, (unsigned long long)(depth * tokens),
           p.tpsA, p.tpsB, p.wallA, p.wallB,
           (unsigned long long)p.readA, (unsigned long long)p.readB,
           (unsigned long long)p.hitsB, (unsigned long long)p.cachePeakB,
           (p.okA && p.okB && p.tpsB > p.tpsA && p.readB < p.readA) ? 1 : 0);
    fflush(stdout);
    return p;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_LIVE_POLICY", "MANUAL"); // cert owns A/B arms
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_LIVE_POLICY_CROSSOVER_001", nullptr);
    printf("K2_LIVE_POLICY_CROSSOVER_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_LIVE_POLICY_CROSSOVER_001=SKIP\n"); return 0;
    }
    // Quick re-validate after sweep (no 20+ min matrix).
    if (const char* q = std::getenv("DEEP2_CROSSOVER_QUICK"); q && q[0] == '1') {
        uint64_t cross = 8;
        if (const char* c = std::getenv("DEEP2_LIVE_CROSSOVER_STEPS")) {
            long v = atol(c); if (v > 0) cross = (uint64_t)v;
        }
        K2LivePolicy_SetCrossoverSteps(cross);
        // Independent workload points: clear sticky between Decide calls.
        K2LivePolicy_ClearSticky();
        auto dTiny = K2LivePolicy_Decide(1, 1);
        K2LivePolicy_ClearSticky();
        auto dShallow = K2LivePolicy_Decide(4, 2);
        K2LivePolicy_ClearSticky();
        auto dHi = K2LivePolicy_Decide(61, 8);
        K2LivePolicy_Emit(stdout, dTiny);
        K2LivePolicy_Emit(stdout, dShallow);
        K2LivePolicy_Emit(stdout, dHi);
        const bool ok =
            dTiny.mode == K2LivePolicyMode::Off &&
            dShallow.mode == K2LivePolicyMode::TrampolineOutput &&
            dShallow.layerVeto == 0 &&
            dShallow.arm && std::strcmp(dShallow.arm, "TRAMPOLINE_OUTPUT_CACHE") == 0 &&
            dHi.mode == K2LivePolicyMode::TrampolineOutput &&
            dHi.layerVeto == 1 &&
            dHi.arm && std::strcmp(dHi.arm, "FULL_DEPTH_PROMO") == 0;
        printf("K2_LIVE_POLICY_CROSSOVER_STEPS=%llu\n", (unsigned long long)cross);
        printf("K2_LIVE_POLICY_CROSSOVER_001=%s\n", ok ? "PASS" : "FAIL");
        fflush(stdout);
        _exit(ok ? 0 : 2);
    }
    static const char* kPrompt =
        "Write one short paragraph on local decode tok/s.";
    Deep2Engine* e = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!e->initialize(cfg) || !e->openK2ShardDirectory(dir)) {
        printf("K2_LIVE_POLICY_CROSSOVER_001=FAIL open\n"); return 2;
    }
    // Sparse sweep (skip 61 here — use prior full-depth witnesses).
    const uint32_t pts[][2] = {
        {4, 2}, {4, 4}, {4, 8},
        {8, 2}, {8, 4}, {8, 8},
        {16, 4}, {16, 8},
    };
    std::vector<Point> rows;
    uint64_t minWinSteps = 0;
    for (auto& pt : pts) {
        Point p = RunPair(*e, kPrompt, pt[0], pt[1]);
        rows.push_back(p);
        const uint64_t steps = (uint64_t)pt[0] * pt[1];
        const bool win = p.okA && p.okB && p.tpsB > p.tpsA && p.readB < p.readA;
        if (win && (minWinSteps == 0 || steps < minWinSteps))
            minWinSteps = steps;
    }
    // Crossover = smallest winning reuse-steps (or keep 32 if none).
    const uint64_t cross = minWinSteps ? minWinSteps : 32;
    K2LivePolicy_SetCrossoverSteps(cross);
    printf("K2_LIVE_POLICY_CROSSOVER_STEPS=%llu\n", (unsigned long long)cross);
    printf("K2_LIVE_POLICY_RULE=reuse_steps=depth*tokens; "
           "steps<crossover -> OFF; shallow -> TRAMPOLINE_OUTPUT_CACHE; "
           "full-depth layer veto -> FULL_DEPTH_PROMO\n");
    // Sanity: independent points (clear sticky between).
    K2LivePolicy_ClearSticky();
    auto dTiny = K2LivePolicy_Decide(1, 1);
    K2LivePolicy_ClearSticky();
    auto dShallow = K2LivePolicy_Decide(4, 2);
    K2LivePolicy_ClearSticky();
    auto dHi = K2LivePolicy_Decide(61, 8);
    K2LivePolicy_Emit(stdout, dTiny);
    K2LivePolicy_Emit(stdout, dShallow);
    K2LivePolicy_Emit(stdout, dHi);
    const bool policyOk =
        dTiny.mode == K2LivePolicyMode::Off &&
        dShallow.mode == K2LivePolicyMode::TrampolineOutput &&
        dShallow.arm && std::strcmp(dShallow.arm, "TRAMPOLINE_OUTPUT_CACHE") == 0 &&
        dHi.mode == K2LivePolicyMode::TrampolineOutput &&
        dHi.layerVeto == 1 &&
        dHi.arm && std::strcmp(dHi.arm, "FULL_DEPTH_PROMO") == 0 &&
        minWinSteps > 0;
    printf("K2_LIVE_POLICY_CROSSOVER_001=%s\n", policyOk ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_LIVE_POLICY_CROSSOVER_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "CROSSOVER_STEPS=%llu\n", (unsigned long long)cross);
        for (const auto& p : rows) {
            fprintf(f,
                "d=%u t=%u TPS_D=%.4f WALL_D=%.1f READ_D=%lld HITS=%llu PEAK=%llu\n",
                p.depth, p.tokens, p.tpsB - p.tpsA, p.wallB - p.wallA,
                (long long)p.readB - (long long)p.readA,
                (unsigned long long)p.hitsB, (unsigned long long)p.cachePeakB);
        }
        fprintf(f, "K2_LIVE_POLICY_CROSSOVER_001=%s\n", policyOk ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(policyOk ? 0 : 2);
}
