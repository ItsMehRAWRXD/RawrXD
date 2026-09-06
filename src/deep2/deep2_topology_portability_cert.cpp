// deep2_topology_portability_cert.cpp — 0/1/N + override without SKU hard-codes
#define _CRT_SECURE_NO_WARNINGS
#include "Deep2DeviceManager.hpp"
#include "Deep2Engine.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

namespace {

void ClearGpuEnv() {
#ifdef _WIN32
    _putenv_s("RAWRXD_GPU_POLICY", "");
    _putenv_s("DEEP2_GPU_POLICY", "");
    _putenv_s("RAWRXD_GPU_DEVICES", "");
    _putenv_s("DEEP2_GPU_DEVICES", "");
    _putenv_s("DEEP2_GPU_SELECT", "");
    _putenv_s("RAWRXD_GPU_SELECT", "");
    _putenv_s("RAWRXD_GPU_NAME", "");
#endif
}

void SetEnv(const char* k, const char* v) {
#ifdef _WIN32
    // CRT getenv reads the CRT environ block; Win32 SetEnvironmentVariable alone is insufficient.
    _putenv_s(k, v ? v : "");
#else
    if (v && *v) setenv(k, v, 1); else unsetenv(k);
#endif
}

bool HasTokenI(const char* hay, const char* needle) {
    if (!hay || !needle || !*needle) return false;
    for (; *hay; ++hay) {
        const char* a = hay; const char* b = needle;
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
            if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
            if (ca != cb) break;
            ++a; ++b;
        }
        if (!*b) return true;
    }
    return false;
}

// Distinctive token: length>=4 and not a shared vendor/family word.
bool DistinctiveMatch(const char* wantName, const char* openedName, const char* excludeName) {
    const char* t = wantName;
    while (*t) {
        while (*t == ' ' || *t == '(' || *t == ')') ++t;
        char tok[32]{};
        size_t k = 0;
        while (*t && *t != ' ' && *t != '(' && *t != ')' && k + 1 < sizeof(tok))
            tok[k++] = *t++;
        if (k < 4) continue;
        if (HasTokenI("AMD RADEON GRAPHICS SERIES", tok)) continue;
        if (excludeName && HasTokenI(excludeName, tok)) continue;
        if (HasTokenI(openedName, tok)) return true;
    }
    return false;
}

struct Ranked {
    int index = -1;
    unsigned score = 0;
    uint64_t vram = 0;
};

void RankDiscrete(const DeviceManagerSnapshot& snap, Ranked* out, unsigned& n) {
    n = 0;
    for (unsigned i = 0; i < snap.deviceCount && n < 8; ++i) {
        if (snap.devices[i].integrated || snap.devices[i].score < 10) continue;
        out[n].index = snap.devices[i].index;
        out[n].score = snap.devices[i].score;
        out[n].vram = snap.devices[i].dedicatedVram;
        ++n;
    }
    for (unsigned a = 0; a + 1 < n; ++a) {
        for (unsigned b = a + 1; b < n; ++b) {
            if (out[b].score > out[a].score ||
                (out[b].score == out[a].score && out[b].vram > out[a].vram)) {
                Ranked t = out[a]; out[a] = out[b]; out[b] = t;
            }
        }
    }
}

bool PlanCase(const char* name, const char* devices, const char* select,
              unsigned expectOpenedMin, unsigned expectOpenedMax,
              ExecMode expectMode, bool* okOut, FILE* log) {
    ClearGpuEnv();
    SetEnv("RAWRXD_GPU_POLICY", "AUTO");
    if (devices) SetEnv("RAWRXD_GPU_DEVICES", devices);
    if (select) SetEnv("DEEP2_GPU_SELECT", select);

    DeviceManagerSnapshot snap{};
    Deep2Device_Enumerate(snap);
    Deep2Device_ApplyPolicy(snap);
    const DevicePlan& p = snap.plan;
    const bool ok =
        p.opened >= expectOpenedMin && p.opened <= expectOpenedMax &&
        p.mode == expectMode &&
        (expectOpenedMin == 0 ? p.primaryIndex < 0 : p.primaryIndex >= 0);

    printf("CASE=%s opened=%u mode=%u reason=%s primary=%s OK=%d\n",
           name, p.opened, (unsigned)p.mode, p.reason,
           p.primaryIndex >= 0 ? p.primaryName : "(none)", ok ? 1 : 0);
    if (log) {
        fprintf(log, "CASE=%s\nDEEP2_DEVICE_COUNT_DETECTED=%u\nDEEP2_DEVICE_COUNT_OPENED=%u\n",
                name, p.detected, p.opened);
        fprintf(log, "DEEP2_EXEC_PATH=%s\nDEEP2_PLAN_REASON=%s\nDEEP2_PRIMARY_NAME=%s\nOK=%d\n",
                p.mode == ExecMode::CpuNative ? "CPU_NATIVE"
                : p.mode == ExecMode::SingleGpu ? "SINGLE_GPU"
                : p.mode == ExecMode::MultiGpuShard ? "MULTIGPU" : "OTHER",
                p.reason,
                p.primaryIndex >= 0 ? p.primaryName : "(none)",
                ok ? 1 : 0);
    }
    *okOut = ok;
    return ok;
}

size_t RunGen(Deep2Engine& engine, const char* prompt, int maxTok) {
    GenerationOptions opts{};
    opts.maxTokens = maxTok; opts.temperature = 0.0f; opts.topK = 1; opts.seed = 42;
    size_t n = 0;
    engine.generateStream(prompt, opts, [&](int32_t, const std::string&) -> bool {
        ++n; return true;
    });
    return n;
}

} // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_TOPOLOGY_001 / STREAMER_GPU_SOLO_002\nModel: %s\n", model);

    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_TOPOLOGY_001", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_SOLO_002", nullptr);
    FILE* log = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_TOPOLOGY_001\\PLAN_CASES.txt", "w");

    ClearGpuEnv();
    DeviceManagerSnapshot base{};
    Deep2Device_Enumerate(base);
    Ranked ranked[8]{};
    unsigned rankedN = 0;
    RankDiscrete(base, ranked, rankedN);
    printf("DETECTED=%u DISCRETE_RANKED=%u\n", base.deviceCount, rankedN);
    for (unsigned i = 0; i < rankedN; ++i) {
        printf("RANK_%u index=%d score=%u vram=%llu name=%s id=%s\n",
               i, ranked[i].index, ranked[i].score,
               (unsigned long long)ranked[i].vram,
               base.devices[ranked[i].index].name,
               base.devices[ranked[i].index].stableId);
    }

    bool allOk = true;
    bool c = false;

    // 0 GPUs policy path
    PlanCase("CPU_FORCE", "CPU", nullptr, 0, 0, ExecMode::CpuNative, &c, log);
    allOk = allOk && c;

    // 1 GPU AUTO
    PlanCase("AUTO_BEST", nullptr, nullptr, 1, 1, ExecMode::SingleGpu, &c, log);
    allOk = allOk && c;
    char bestIdx[16]{};
    char secondIdx[16]{};
    const char* secondStable = nullptr;
    const char* bestStable = nullptr;
    if (rankedN >= 1) {
        std::snprintf(bestIdx, sizeof(bestIdx), "%d", ranked[0].index);
        bestStable = base.devices[ranked[0].index].stableId;
    }
    if (rankedN >= 2) {
        std::snprintf(secondIdx, sizeof(secondIdx), "%d", ranked[1].index);
        secondStable = base.devices[ranked[1].index].stableId;
    }

    if (rankedN >= 1) {
        PlanCase("INDEX_BEST", bestIdx, nullptr, 1, 1, ExecMode::SingleGpu, &c, log);
        allOk = allOk && c;
        PlanCase("STABLE_BEST", nullptr, bestStable, 1, 1, ExecMode::SingleGpu, &c, log);
        allOk = allOk && c;
    }

    if (rankedN >= 2) {
        PlanCase("INDEX_SECOND", secondIdx, nullptr, 1, 1, ExecMode::SingleGpu, &c, log);
        allOk = allOk && c;
        PlanCase("STABLE_SECOND", nullptr, secondStable, 1, 1, ExecMode::SingleGpu, &c, log);
        allOk = allOk && c;
        PlanCase("ALL_DISCRETE", "ALL", nullptr, 2, 8, ExecMode::MultiGpuShard, &c, log);
        allOk = allOk && c;
    } else {
        printf("SKIP_SECOND=need_two_discrete\n");
        if (log) fprintf(log, "SKIP_SECOND=need_two_discrete\n");
    }

    // SOLO_002: resident GEMV on second-ranked discrete via stable-id override
    unsigned solo2Pass = 0;
    double solo2Tps = 0.0;
    std::string solo2Name = "(skipped)";
    uint64_t solo2Hits = 0, solo2Up = 0, solo2Fail = 0;
    if (rankedN >= 2 && secondStable) {
        ClearGpuEnv();
        SetEnv("RAWRXD_GPU_POLICY", "AUTO");
        SetEnv("DEEP2_GPU_SELECT", secondStable);
        Deep2Engine engine;
        if (!engine.loadModel(model)) {
            printf("SOLO_002 FAIL loadModel\n");
            allOk = false;
        } else {
            const auto& mw = engine.getModelWeights();
            EngineConfig cfg{};
            cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
            cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
            cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
            cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
            cfg.numThreads = 16;
            if (!engine.initialize(cfg) || (engine.enableVulkan(true), !engine.isVulkanEnabled())) {
                printf("SOLO_002 FAIL vulkan open on override primary\n");
                allOk = false;
            } else {
                auto* vc = engine.getVulkanCompute();
                solo2Name = vc ? vc->GetDeviceInfo().device_name : "(none)";
                const char* bestName = base.devices[ranked[0].index].name;
                const char* secondName = base.devices[ranked[1].index].name;
                const bool matchedSecond = DistinctiveMatch(secondName, solo2Name.c_str(), bestName);
                const bool matchedBest = DistinctiveMatch(bestName, solo2Name.c_str(), secondName);
                RunGen(engine, "hi", 1);
                auto t0 = std::chrono::steady_clock::now();
                size_t n = RunGen(engine, "hello", 15);
                auto t1 = std::chrono::steady_clock::now();
                double sec = std::chrono::duration<double>(t1 - t0).count();
                solo2Tps = (n > 0 && sec > 0) ? (double)n / sec : 0.0;
                solo2Fail = engine.vulkanGemvFallbackCount();
                solo2Up = vc ? vc->GemvWeightUploads() : 0;
                solo2Hits = vc ? vc->GemvWeightHits() : 0;
                const uint64_t okGemv = engine.vulkanGemvSuccessCount();
                solo2Pass = (matchedSecond && !matchedBest && solo2Fail == 0 && okGemv > 1 &&
                             solo2Up > 0 && solo2Hits > solo2Up && n > 0) ? 1u : 0u;
                printf("SOLO_002_SELECTED=%s matched_second=%d matched_best=%d\n",
                       solo2Name.c_str(), matchedSecond ? 1 : 0, matchedBest ? 1 : 0);
                printf("SOLO_002_UPLOADS=%llu HITS=%llu FAIL=%llu warm_tps=%.3f PASS=%u\n",
                       (unsigned long long)solo2Up, (unsigned long long)solo2Hits,
                       (unsigned long long)solo2Fail, solo2Tps, solo2Pass);
                allOk = allOk && (solo2Pass == 1);
                FILE* s2 = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_SOLO_002\\DECODE_TINYLLAMA.txt", "w");
                if (s2) {
                    fprintf(s2, "STREAMER_GPU_SOLO_002=%s\n", solo2Pass ? "PASS" : "FAIL");
                    fprintf(s2, "DEEP2_SELECT_STABLE_ID=%s\n", secondStable);
                    fprintf(s2, "DEEP2_GPU_SELECTED=%s\n", solo2Name.c_str());
                    fprintf(s2, "DEEP2_CPU_FALLBACK_USED=%u\n", solo2Fail > 0 ? 1u : 0u);
                    fprintf(s2, "DEEP2_GPU_WEIGHT_UPLOADS=%llu\n", (unsigned long long)solo2Up);
                    fprintf(s2, "DEEP2_GPU_WEIGHT_HITS=%llu\n", (unsigned long long)solo2Hits);
                    fprintf(s2, "warm_multi15_e2e_tok_s=%.3f\n", solo2Tps);
                    fprintf(s2, "PASS=%u\n", solo2Pass);
                    fclose(s2);
                }
            }
        }
    }

    printf("TOPOLOGY_PORTABILITY=%s\n", allOk ? "PASS" : "FAIL");
    printf("STREAMER_GPU_SOLO_002=%s\n", rankedN < 2 ? "SKIP" : (solo2Pass ? "PASS" : "FAIL"));
    if (log) {
        fprintf(log, "TOPOLOGY_PORTABILITY=%s\nSTREAMER_GPU_SOLO_002=%s\n",
                allOk ? "PASS" : "FAIL",
                rankedN < 2 ? "SKIP" : (solo2Pass ? "PASS" : "FAIL"));
        fclose(log);
    }
    FILE* gs = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_TOPOLOGY_001\\GATE_STATUS.txt", "w");
    if (gs) {
        fprintf(gs, "STREAMER_TOPOLOGY_001=%s\n", allOk ? "PASS" : "FAIL");
        fprintf(gs, "STREAMER_GPU_SOLO_002=%s\n", rankedN < 2 ? "SKIP" : (solo2Pass ? "PASS" : "FAIL"));
        fprintf(gs, "DISCRETE_RANKED=%u\n", rankedN);
        fprintf(gs, "NOTE=capability/policy only; no SKU hard-codes\n");
        fclose(gs);
    }
    return allOk ? 0 : 2;
}
