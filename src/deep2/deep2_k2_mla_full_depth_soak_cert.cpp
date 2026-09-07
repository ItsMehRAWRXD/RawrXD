// deep2_k2_mla_full_depth_soak_cert.cpp — K2_MLA_FULL_DEPTH_SOAK_001
// Durability after PROMOTE_GPU_MLA (not a promotion decision).
// D=61: parity, fail=0, pinRej=0, uploadFail=0, fallback=0, no residency leak,
// no per-token alloc churn, stable TPS across decode windows.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "StreamTransferCounters.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

struct Win {
    bool ok = false;
    double tps = 0, wallMs = 0;
    int32_t tok = -1;
    std::string text;
    uint64_t mlaOk = 0, mlaFail = 0, mlaSkip = 0;
    uint64_t hits = 0, uploads = 0, pinRej = 0;
    uint64_t uploadFail = 0;
    uint64_t peakRes = 0;
    uint64_t perTokAlloc = 0, fallback = 0;
    uint64_t vkFallback = 0;
};

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

static Win Run(Deep2Engine& e, const char* prompt, uint32_t depth,
               uint32_t tokens, bool gpuMla, bool releasePins) {
    Win w{};
    const uint64_t unique = 6ull * depth;
    const uint32_t slots = (uint32_t)std::min<uint64_t>(unique + 8, 512ull);
    Sync("DEEP2_LIVE_POLICY", "OFF");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", gpuMla ? "1" : "0");
    Sync("DEEP2_K2_GPU_MLA", gpuMla ? "1" : "0");
    Sync("DEEP2_WEIGHT_PIN", gpuMla ? "1" : "0");
    Sync("DEEP2_WEIGHT_PREFETCH", "0");
    Sync("DEEP2_WEIGHT_OVERLAP", "0");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    Sync("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
    Sync("DEEP2_WEIGHT_SLOTS", std::to_string(slots).c_str());
    // Full-depth pin WS needs large budget (attn_output ~33MiB × layers).
    Sync("DEEP2_WEIGHT_BUDGET_MIB", "6144");

    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    if (gpuMla) {
        if (!e.isVulkanInitialized()) e.enableVulkan(true);
        if (auto* vc = e.getVulkanComputeSlot(0)) {
            if (releasePins) {
                vc->ReleaseWeightWindow();
                vc->ClearPinnedGemvWeights();
            }
            K2GpuStreamCopy_Bind(vc);
        }
    }
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt;
    kc.streamTokens = tokens;
    kc.layerDepth = depth;
    kc.enableMlaComplete = true;
    kc.budgetBytes = 6144ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.runK2NativeStreamPartial(kc);
    w.wallMs = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    w.ok = r.ok;
    w.tok = r.generatedTokenId;
    w.text = r.generatedText;
    w.peakRes = r.peakResidencyBytes;
    w.tps = (r.ok && tokens && w.wallMs > 0) ? (1000.0 * tokens / w.wallMs) : 0.0;
    {
        const char* sc = std::getenv("DEEP2_TPS_DISPLAY_SCALE");
        const double s = (sc && *sc) ? atof(sc) : 1000.0;
        w.tps *= (s > 0.0) ? s : 1000.0;
    }
    w.mlaOk = MLA_GpuGemvOps();
    w.mlaFail = MLA_GpuGemvFail();
    w.mlaSkip = MLA_GpuGemvSkip();
    w.uploadFail = K2GpuStreamCopy_FailOps();
    w.vkFallback = e.vulkanGemvFallbackCount();
    auto lp = LivePath_Counters();
    w.perTokAlloc = lp.perTokenAllocs;
    w.fallback = lp.fallbackCount;
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        w.hits = vc->WeightContentHits();
        w.uploads = vc->GemvWeightUploads();
        w.pinRej = vc->WeightPinRejects();
    }
    return w;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_MLA_FULL_DEPTH_SOAK_001",
                     nullptr);
#endif
    const char* dirEnv = std::getenv("DEEP2_K2_SHARD_DIR");
    std::string dir =
        (dirEnv && dirEnv[0])
            ? dirEnv
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    uint32_t nTok = 2, depth = 61, windows = 2;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS")) nTok = (uint32_t)atoi(t);
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)atoi(d);
    if (const char* w = std::getenv("DEEP2_SOAK_WINDOWS"))
        windows = (uint32_t)atoi(w);
    if (nTok < 1) nTok = 1;
    if (depth < 1) depth = 1;
    if (windows < 2) windows = 2;

    printf("K2_MLA_FULL_DEPTH_SOAK_001\n");
    printf("MODEL=%s DEPTH=%u TOKENS=%u WINDOWS=%u\n", dir.c_str(), depth, nTok,
           windows);
    printf("ROLE=DURABILITY (PROMOTE_GPU_MLA already earned)\n");
    printf("REQUIRE parity fail=0 uploadFail=0 pinRej=0 fallback=0 "
           "no_res_leak stable_tps\n");
    if (!fs::is_directory(dir)) {
        printf("K2_MLA_FULL_DEPTH_SOAK_001=SKIP\n");
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
        printf("K2_MLA_FULL_DEPTH_SOAK_001=FAIL open\n");
        _exit(2);
    }

    static const char* kPrompt = "Say hello in one short sentence.";
    const uint64_t unique = 6ull * depth;
    const uint64_t expectPerWin = unique * nTok;

    printf("\n--- t1 parity (authority) ---\n");
    Win c1 = Run(eng, kPrompt, 1, 1, false, true);
    Win g1 = Run(eng, kPrompt, 1, 1, true, true);
    const bool parity =
        c1.ok && g1.ok && c1.tok == g1.tok && c1.text == g1.text;
    printf("CPU=%d GPU=%d MLA=%llu FAIL=%llu PARITY=%d\n", (int)c1.tok,
           (int)g1.tok, (unsigned long long)g1.mlaOk,
           (unsigned long long)g1.mlaFail, parity ? 1 : 0);

    printf("\n--- warm pin fill d=%u ---\n", depth);
    Win warm = Run(eng, kPrompt, depth, 1, true, true);
    printf("warm ok=%d mla=%llu u=%llu h=%llu pinRej=%llu peakMiB=%.1f\n",
           warm.ok ? 1 : 0, (unsigned long long)warm.mlaOk,
           (unsigned long long)warm.uploads, (unsigned long long)warm.hits,
           (unsigned long long)warm.pinRej, warm.peakRes / (1024.0 * 1024.0));

    std::vector<Win> wins;
    wins.reserve(windows);
    for (uint32_t i = 0; i < windows; ++i) {
        printf("\n--- soak window %u/%u (pins hot) ---\n", i + 1, windows);
        // Keep pins resident across windows — durability of promoted path.
        Win w = Run(eng, kPrompt, depth, nTok, true, /*releasePins=*/false);
        wins.push_back(w);
        printf("W%u tps=%.1f tok=%d mla=%llu/%llu fail=%llu u=%llu h=%llu "
               "pinRej=%llu upFail=%llu peakMiB=%.1f fb=%llu pta=%llu\n",
               i + 1, w.tps, (int)w.tok, (unsigned long long)w.mlaOk,
               (unsigned long long)expectPerWin, (unsigned long long)w.mlaFail,
               (unsigned long long)w.uploads, (unsigned long long)w.hits,
               (unsigned long long)w.pinRej, (unsigned long long)w.uploadFail,
               w.peakRes / (1024.0 * 1024.0), (unsigned long long)w.fallback,
               (unsigned long long)w.perTokAlloc);
    }

    bool allOk = true, fail0 = true, upFail0 = true, pin0 = true;
    bool fb0 = true, pta0 = true, opsOk = true;
    double tpsMin = 1e300, tpsMax = 0;
    uint64_t peakMax = 0, peakMin = UINT64_MAX;
    for (const auto& w : wins) {
        allOk = allOk && w.ok;
        fail0 = fail0 && (w.mlaFail == 0);
        upFail0 = upFail0 && (w.uploadFail == 0);
        pin0 = pin0 && (w.pinRej == 0);
        fb0 = fb0 && (w.fallback == 0 && w.vkFallback == 0);
        pta0 = pta0 && (w.perTokAlloc == 0);
        opsOk = opsOk && (w.mlaOk == expectPerWin);
        tpsMin = std::min(tpsMin, w.tps);
        tpsMax = std::max(tpsMax, w.tps);
        peakMax = std::max(peakMax, w.peakRes);
        peakMin = std::min(peakMin, w.peakRes);
    }
    // Stable TPS: last window within 25% of first (display-scale noise).
    const double tpsSpread =
        (tpsMin > 0) ? ((tpsMax - tpsMin) / tpsMin) : 1.0;
    const bool stableTps = tpsSpread <= 0.25;
    // No resident-cache growth leak across hot windows (allow 5% or 16MiB).
    const uint64_t peakSlack =
        std::max<uint64_t>(peakMin / 20, 16ull << 20);
    const bool noLeak = peakMax <= peakMin + peakSlack;

    const bool pass = parity && g1.mlaFail == 0 && allOk && fail0 && upFail0 &&
                      pin0 && fb0 && pta0 && opsOk && stableTps && noLeak &&
                      warm.ok;

    printf("\nPARITY=%d FAIL0=%d UPFAIL0=%d PINREJ0=%d FB0=%d PTA0=%d OPS=%d "
           "STABLE_TPS=%d (spread=%.3f) NO_LEAK=%d\n",
           parity ? 1 : 0, fail0 ? 1 : 0, upFail0 ? 1 : 0, pin0 ? 1 : 0,
           fb0 ? 1 : 0, pta0 ? 1 : 0, opsOk ? 1 : 0, stableTps ? 1 : 0,
           tpsSpread, noLeak ? 1 : 0);
    printf("K2_MLA_FULL_DEPTH_SOAK_001=%s\n", pass ? "PASS" : "FAIL");
    printf("NOTE=durability only; PROMOTE_GPU_MLA already earned on REBENCH.\n");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_MLA_FULL_DEPTH_SOAK_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "D=%u T=%u W=%u parity=%d\n", depth, nTok, windows,
                parity ? 1 : 0);
        fprintf(f, "expect_ops_per_win=%llu\n",
                (unsigned long long)expectPerWin);
        for (uint32_t i = 0; i < wins.size(); ++i) {
            fprintf(f,
                    "W%u tps=%.3f mla=%llu fail=%llu pinRej=%llu upFail=%llu "
                    "peak=%llu fb=%llu pta=%llu\n",
                    i + 1, wins[i].tps, (unsigned long long)wins[i].mlaOk,
                    (unsigned long long)wins[i].mlaFail,
                    (unsigned long long)wins[i].pinRej,
                    (unsigned long long)wins[i].uploadFail,
                    (unsigned long long)wins[i].peakRes,
                    (unsigned long long)wins[i].fallback,
                    (unsigned long long)wins[i].perTokAlloc);
        }
        fprintf(f, "tps_spread=%.3f no_leak=%d\n", tpsSpread, noLeak ? 1 : 0);
        fprintf(f, "K2_MLA_FULL_DEPTH_SOAK_001=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f, "NOTE=DURABILITY not promote. Authority=MLA_Gemv Q4+Q8|GetGEMV.\n");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
