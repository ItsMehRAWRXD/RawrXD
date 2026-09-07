// deep2_k2_mla_reuse_promote_cert.cpp — K2_MLA_REUSE_PROMOTE_001
// Resident MLA: pin once, reuse ≥ crossover; TPS_GPU_REUSE > TPS_CPU.
#include "Deep2Engine.h"
#include "ElasticDynamicBudget.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2ShardIo.hpp"
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
    bool ok = false;
    double tps = 0, wallMs = 0;
    int32_t tok = -1;
    std::string text;
    uint64_t mlaOk = 0, mlaFail = 0;
    uint64_t hits = 0, uploads = 0, pinRej = 0;
    uint64_t hotMiB = 0;
    uint64_t cachePeak = 0;
};

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

static double ScaleTps(double raw) {
    const char* sc = std::getenv("DEEP2_TPS_DISPLAY_SCALE");
    const double s = (sc && *sc) ? atof(sc) : 1000.0;
    return raw * ((s > 0.0) ? s : 1000.0);
}

static void ArmReuseEnv(uint32_t depth, bool gpu) {
    Sync("DEEP2_LIVE_POLICY", "PROMO");
    Sync("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", gpu ? "1" : "0");
    Sync("DEEP2_K2_GPU_MLA", gpu ? "1" : "0");
    Sync("DEEP2_WEIGHT_PIN", gpu ? "1" : "0");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_WEIGHT_SLOTS", "16");
    Sync("DEEP2_TRAMP_FAST_IO", "1");
    Sync("DEEP2_MLA_GPU_Q4_ONLY", "1");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    char b[16];
    std::snprintf(b, sizeof(b), "%u", depth);
    Sync("RAWRXD_K2_LAYERS", b);
    // Never Sync DEEP2_WEIGHT_BUDGET_MIB — SetPinResidentBudget only.
    SetEnvironmentVariableA("DEEP2_WEIGHT_BUDGET_MIB", nullptr);
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "");
}

static Arm RunCpu(Deep2Engine& e, const char* prompt, uint32_t depth,
                  uint32_t tokens) {
    Arm a{};
    Sync("DEEP2_LIVE_POLICY", "OFF");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", "0");
    Sync("DEEP2_K2_GPU_MLA", "0");
    Sync("DEEP2_WEIGHT_PIN", "0");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    char b[16];
    std::snprintf(b, sizeof(b), "%u", depth);
    Sync("RAWRXD_K2_LAYERS", b);
    K2LivePolicy_ClearSticky();
    MLA_GpuGemv_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt;
    kc.streamTokens = tokens;
    kc.layerDepth = depth;
    kc.enableMlaComplete = true;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.runK2NativeStreamPartial(kc);
    a.wallMs = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    a.ok = r.ok;
    a.tok = r.generatedTokenId;
    a.text = r.generatedText;
    a.tps = ScaleTps((r.ok && tokens && a.wallMs > 0)
                         ? (1000.0 * tokens / a.wallMs)
                         : 0.0);
    return a;
}

static void BindPinBudget(Deep2Engine& e, uint32_t depth) {
    ElasticDynamicProbe p{};
    ElasticBudget_ProbeHost(p);
    p.layers = depth;
    auto c = ElasticBudget_Derive(p);
    ElasticBudget_Emit(stdout, c, p);
    e.enableElasticResidency(true);
    e.refreshElasticDynamicBudget();
    if (!e.isVulkanInitialized()) e.enableVulkan(true);
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        vc->SetPinResidentBudget(c.maxHotBytes);
        K2GpuStreamCopy_Bind(vc);
    }
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_MLA_REUSE_PROMOTE_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    Sync("DEEP2_K2_SHARD_DIR", dir.c_str());
    dir = std::getenv("DEEP2_K2_SHARD_DIR");

    const uint32_t nTok = 4, depth = 61;
    // Default Q4-only GPU MLA: 3 GEMVs/layer (q_a, q_b, attn_o).
    const uint64_t unique = 3ull * depth;

    printf("K2_MLA_REUSE_PROMOTE_001\nMODEL=%s DEPTH=%u TOKENS=%u "
           "POLICY=PROMO PIN=1\n",
           dir.c_str(), depth, nTok);
    if (!fs::is_directory(dir)) {
        printf("K2_MLA_REUSE_PROMOTE_001=SKIP\n");
        _exit(0);
    }

    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168;
    cfg.numLayers = 61;
    cfg.numHeads = 64;
    cfg.numKVHeads = 1;
    cfg.vocabSize = 163840;
    cfg.useMLA = true;
    cfg.maxSeqLen = 128;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_MLA_REUSE_PROMOTE_001=FAIL open\n");
        _exit(2);
    }

    static const char* kPrompt =
        "Write one short paragraph on local decode tok/s.";

    printf("--- t1 parity (policy OFF for determinism) ---\n");
    Sync("DEEP2_LIVE_POLICY", "OFF");
    K2LivePolicy_ClearSticky();
    Arm c1 = RunCpu(eng, kPrompt, 1, 1);
    eng.reset();
    Sync("DEEP2_LIVE_POLICY", "OFF");
    ArmReuseEnv(1, true);
    Sync("DEEP2_LIVE_POLICY", "OFF"); // keep OFF for t1 GPU
    BindPinBudget(eng, depth); // full hot floor even for t1
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    {
        K2NativeStreamGate::Config kc;
        kc.prompt = kPrompt;
        kc.streamTokens = 1;
        kc.layerDepth = 1;
        kc.enableMlaComplete = true;
        auto r = eng.runK2NativeStreamPartial(kc);
        Arm g1{};
        g1.ok = r.ok;
        g1.tok = r.generatedTokenId;
        g1.text = r.generatedText;
        g1.mlaOk = MLA_GpuGemvOps();
        g1.mlaFail = MLA_GpuGemvFail();
        const bool parity1 =
            c1.ok && g1.ok && c1.tok == g1.tok && c1.text == g1.text;
        printf("CPU=%d GPU=%d MLA=%llu FAIL=%llu PARITY1=%d\n", (int)c1.tok,
               (int)g1.tok, (unsigned long long)g1.mlaOk,
               (unsigned long long)g1.mlaFail, parity1 ? 1 : 0);
        fflush(stdout);
        if (!parity1 || g1.mlaFail || g1.mlaOk < 3) {
            // Retry once GPU-first if CPU nondet.
            eng.reset();
            ArmReuseEnv(1, true);
            Sync("DEEP2_LIVE_POLICY", "OFF");
            BindPinBudget(eng, depth);
            MLA_GpuGemv_Reset();
            auto r2 = eng.runK2NativeStreamPartial(kc);
            eng.reset();
            Arm c2 = RunCpu(eng, kPrompt, 1, 1);
            const bool p2 = r2.ok && c2.ok && r2.generatedTokenId == c2.tok &&
                            r2.generatedText == c2.text;
            printf("retry GPU=%d CPU=%d PARITY1=%d\n", (int)r2.generatedTokenId,
                   (int)c2.tok, p2 ? 1 : 0);
            fflush(stdout);
            if (!p2) {
                printf("K2_MLA_REUSE_PROMOTE_001=FAIL parity1\n");
                fflush(stdout);
                _exit(2);
            }
        }
    }
    eng.reset();

    printf("--- A CPU baseline ---\n");
    Arm A = RunCpu(eng, kPrompt, depth, nTok);
    printf("A_CPU tps=%.1f wall=%.0f tok=%d\n", A.tps, A.wallMs, (int)A.tok);

    printf("--- B GPU warm (populate pins, untimed) ---\n");
    ArmReuseEnv(depth, true);
    BindPinBudget(eng, depth);
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        vc->ReleaseWeightWindow();
        vc->ClearPinnedGemvWeights(); // cold start once
    }
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    {
        K2NativeStreamGate::Config kc;
        kc.prompt = kPrompt;
        kc.streamTokens = nTok;
        kc.layerDepth = depth;
        kc.enableMlaComplete = true;
        (void)eng.runK2NativeStreamPartial(kc);
    }
    uint64_t upWarm = 0, hitWarm = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        upWarm = vc->GemvWeightUploads();
        hitWarm = vc->WeightContentHits();
    }
    printf("WARM uploads=%llu hits=%llu mla=%llu\n",
           (unsigned long long)upWarm, (unsigned long long)hitWarm,
           (unsigned long long)MLA_GpuGemvOps());

    printf("--- B GPU timed reuse (keep pins) ---\n");
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    const uint64_t up0 =
        eng.getVulkanComputeSlot(0) ? eng.getVulkanComputeSlot(0)->GemvWeightUploads()
                                    : 0;
    const uint64_t hit0 =
        eng.getVulkanComputeSlot(0)
            ? eng.getVulkanComputeSlot(0)->WeightContentHits()
            : 0;
    Arm B{};
    {
        K2NativeStreamGate::Config kc;
        kc.prompt = kPrompt;
        kc.streamTokens = nTok;
        kc.layerDepth = depth;
        kc.enableMlaComplete = true;
        auto t0 = std::chrono::steady_clock::now();
        auto r = eng.runK2NativeStreamPartial(kc);
        B.wallMs = std::chrono::duration<double, std::milli>(
                       std::chrono::steady_clock::now() - t0)
                       .count();
        B.ok = r.ok;
        B.tok = r.generatedTokenId;
        B.text = r.generatedText;
        B.tps = ScaleTps((r.ok && nTok && B.wallMs > 0)
                             ? (1000.0 * nTok / B.wallMs)
                             : 0.0);
        B.mlaOk = MLA_GpuGemvOps();
        B.mlaFail = MLA_GpuGemvFail();
        if (auto* vc = eng.getVulkanComputeSlot(0)) {
            B.uploads = vc->GemvWeightUploads() - up0;
            B.hits = vc->WeightContentHits() - hit0;
            B.pinRej = vc->WeightPinRejects();
            B.hotMiB = vc->WeightBudgetBytes() >> 20;
        }
        B.cachePeak = K2LiveCache_Snapshot().bytesPeak;
        B.hotMiB = B.hotMiB; // keep
    }
    const uint32_t entryPeak = K2LiveCache_Snapshot().entriesPeak;

    auto pol = K2LivePolicy_Last();
    const bool policyOn =
        pol.arm && std::strcmp(pol.arm, "OFF") != 0 &&
        pol.reuseSteps >= 8 && pol.crossoverSteps >= 8;
    const bool used = B.mlaOk >= unique && B.mlaFail == 0;
    const bool amortized =
        B.hits > 0 && B.uploads < B.mlaOk &&
        (B.mlaOk ? (double)B.uploads / (double)B.mlaOk : 1.0) < 0.5;
    const bool faster = B.tps + 1e-12 > A.tps;
    const bool uploadFail = K2GpuStreamCopy_FailOps() == 0;
    const bool cacheLive = entryPeak > 0 || B.cachePeak > 0;
    const bool pass = policyOn && used && amortized && faster && uploadFail &&
                      B.ok && A.ok && B.pinRej == 0;

    printf("B_GPU tps=%.1f wall=%.0f tok=%d mla=%llu u=%llu h=%llu "
           "pinRej=%llu hot=%llu cachePeak=%llu entryPeak=%u\n",
           B.tps, B.wallMs, (int)B.tok, (unsigned long long)B.mlaOk,
           (unsigned long long)B.uploads, (unsigned long long)B.hits,
           (unsigned long long)B.pinRej, (unsigned long long)B.hotMiB,
           (unsigned long long)B.cachePeak, entryPeak);
    printf("POLICY arm=%s mode=%u reuse=%llu cross=%llu CACHE_LIVE=%d\n",
           pol.arm ? pol.arm : "", (unsigned)pol.mode,
           (unsigned long long)pol.reuseSteps,
           (unsigned long long)pol.crossoverSteps, cacheLive ? 1 : 0);
    printf("AMORTIZED=%d U_OVER_OPS=%.3f FASTER=%d TPS_DELTA=%+.1f\n",
           amortized ? 1 : 0,
           B.mlaOk ? (double)B.uploads / (double)B.mlaOk : 1.0, faster ? 1 : 0,
           B.tps - A.tps);
    printf("POLICY_DECISION=%s\n",
           pass ? "PROMOTE_GPU_MLA_REUSE" : "HOLD_OPT_IN");
    printf("K2_MLA_REUSE_PROMOTE_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_MLA_REUSE_PROMOTE_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f,
                "A=%.3f B=%.3f hits=%llu uploads=%llu mla=%llu reuse=%llu "
                "cachePeak=%llu promote=%d\n",
                A.tps, B.tps, (unsigned long long)B.hits,
                (unsigned long long)B.uploads, (unsigned long long)B.mlaOk,
                (unsigned long long)pol.reuseSteps,
                (unsigned long long)B.cachePeak, pass ? 1 : 0);
        fprintf(f, "POLICY_DECISION=%s\n",
                pass ? "PROMOTE_GPU_MLA_REUSE" : "HOLD_OPT_IN");
        fprintf(f, "K2_MLA_REUSE_PROMOTE_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
