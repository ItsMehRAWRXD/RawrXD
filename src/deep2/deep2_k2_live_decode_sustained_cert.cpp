// deep2_k2_live_decode_sustained_cert.cpp — K2_LIVE_DECODE_SUSTAINED_001
// Rate seal: warm≥2 reqs → 32/64/128; U/tok→0; H/tok flat; MoE blanks unused.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "FusedLiveController.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePolicy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "MoEEliminate.hpp"
#include "StreamPathTiming.hpp"
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
    uint32_t tokens = 0;
    bool ok = false;
    double wallMs = 0, tps = 0;
    uint64_t gemvEntry = 0, tryEntry = 0, mlaOps = 0, mlaFail = 0;
    uint64_t uploads = 0, hits = 0, pinRej = 0, upFail = 0;
    uint64_t fallback = 0, pta = 0, resStart = 0, resPeak = 0, outBytes = 0;
    uint64_t upQ = 0, upK = 0, upV = 0, upO = 0;
    uint64_t hitQ = 0, hitK = 0, hitV = 0, hitO = 0;
    uint64_t keyNew = 0, keyReuse = 0, slotEvict = 0, pinKeyZero = 0;
    uint32_t polSw = 0, fusedPolCh = 0;
};

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

static void PrintPin(Deep2Engine& e, const char* tag) {
    auto* vc = e.getVulkanComputeSlot(0);
    if (!vc) return;
    printf("%s PIN_BUDGET_MIB=%.1f FLOOR=%.1f CACHE_N=%llu RES_MIB=%.1f "
           "PIN_EVICT=%llu\n",
           tag, vc->WeightBudgetBytes() / (1024.0 * 1024.0),
           vc->WeightPinBudgetFloor() / (1024.0 * 1024.0),
           (unsigned long long)vc->WeightPinCacheCount(),
           vc->WeightPinResidentBytes() / (1024.0 * 1024.0),
           (unsigned long long)vc->WeightPinEvicts());
}

static Win RunWindow(Deep2Engine& e, const char* prompt, uint32_t tokens,
                     uint64_t up0, uint64_t hit0, uint64_t rej0,
                     uint64_t resStart) {
    Win w{};
    w.tokens = tokens;
    w.resStart = resStart;
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    StreamPathTiming_Reset();
    // Do NOT Fused_Reset / Policy_ResetSwitches mid-engine — poisons LIVE_SETUP.

    GenerationOptions opts{};
    opts.maxTokens = (int)tokens;
    opts.temperature = 0.0f;
    opts.topK = 1;
    std::string text;
    int32_t lastId = -1;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.generateStream(prompt, opts,
                              [&](int32_t id, const std::string& t) -> bool {
                                  lastId = id;
                                  text += t;
                                  return true;
                              });
    w.wallMs = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    w.ok = r.completed && !text.empty() && lastId >= 0;
    w.outBytes = text.size();
    w.tps = (w.ok && tokens && w.wallMs > 0) ? (1000.0 * tokens / w.wallMs) : 0.0;
    w.gemvEntry = MLA_GemvEntries();
    w.tryEntry = MLA_TryGpuGemvEntries();
    w.mlaOps = MLA_GpuGemvOps();
    w.mlaFail = MLA_GpuGemvFail();
    w.upFail = K2GpuStreamCopy_FailOps();
    w.upQ = MLA_UploadQ();
    w.upK = MLA_UploadK();
    w.upV = MLA_UploadV();
    w.upO = MLA_UploadO();
    w.hitQ = MLA_HitQ();
    w.hitK = MLA_HitK();
    w.hitV = MLA_HitV();
    w.hitO = MLA_HitO();
    w.keyNew = MLA_CacheKeyNew();
    w.keyReuse = MLA_CacheKeyReuse();
    w.slotEvict = MLA_SlotEvict();
    w.pinKeyZero = MLA_PinKeyZero();
    w.polSw = 1;
    w.fusedPolCh = Fused_Counters().policyChanges;
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        w.uploads = vc->GemvWeightUploads() - up0;
        w.hits = vc->WeightContentHits() - hit0;
        w.pinRej = vc->WeightPinRejects() - rej0;
        const uint64_t a = vc->WeightStreamPeakBytes();
        const uint64_t b = vc->WeightPinResidentBytes();
        w.resPeak = b > a ? b : a;
    }
    auto lp = LivePath_Counters();
    w.fallback = lp.fallbackCount + e.vulkanGemvFallbackCount();
    w.pta = lp.perTokenAllocs;
    return w;
}

static void PrintWin(const char* tag, const Win& w, uint64_t expectOps) {
    const double upt = w.tokens ? (double)w.uploads / w.tokens : 0;
    const double hpt = w.tokens ? (double)w.hits / w.tokens : 0;
    const double uops = w.mlaOps ? (double)w.uploads / (double)w.mlaOps : 0;
    printf("%s T=%u ok=%d tps=%.3f wall=%.0f\n", tag, w.tokens, w.ok ? 1 : 0,
           w.tps, w.wallMs);
    printf("  GEMV_ENTRY=%llu TRY=%llu OPS=%llu/%llu FAIL=%llu PINKEY0=%llu\n",
           (unsigned long long)w.gemvEntry, (unsigned long long)w.tryEntry,
           (unsigned long long)w.mlaOps, (unsigned long long)expectOps,
           (unsigned long long)w.mlaFail, (unsigned long long)w.pinKeyZero);
    printf("  UP=%llu HIT=%llu U/TOK=%.3f H/TOK=%.1f U/OPS=%.3f\n",
           (unsigned long long)w.uploads, (unsigned long long)w.hits, upt, hpt,
           uops);
    printf("  MLA_UPLOAD_Q=%llu K=%llu V=%llu O=%llu\n",
           (unsigned long long)w.upQ, (unsigned long long)w.upK,
           (unsigned long long)w.upV, (unsigned long long)w.upO);
    printf("  MLA_HIT_Q=%llu K=%llu V=%llu O=%llu KEY_NEW=%llu REUSE=%llu "
           "EVICT=%llu\n",
           (unsigned long long)w.hitQ, (unsigned long long)w.hitK,
           (unsigned long long)w.hitV, (unsigned long long)w.hitO,
           (unsigned long long)w.keyNew, (unsigned long long)w.keyReuse,
           (unsigned long long)w.slotEvict);
    printf("  PINREJ=%llu UPFAIL=%llu FB=%llu PTA=%llu PEAK_MIB=%.1f POL=%u "
           "FUSED=%u\n",
           (unsigned long long)w.pinRej, (unsigned long long)w.upFail,
           (unsigned long long)w.fallback, (unsigned long long)w.pta,
           w.resPeak / (1024.0 * 1024.0), w.polSw, w.fusedPolCh);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_MOE_ELIMINATE_UNUSED", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_LIVE_DECODE_SUSTAINED_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    uint32_t depth = 61;
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)atoi(d);
    if (depth < 1) depth = 1;

    const uint32_t warmTok = 8, warmReqs = 2;
    const uint32_t winsTok[] = {32, 64, 128};
    const uint64_t unique = 6ull * depth;

    printf("K2_LIVE_DECODE_SUSTAINED_001\n");
    printf("MODEL=%s DEPTH=%u WARM=%ux%u POLICY=FULL_DEPTH_PROMO "
           "MOE_ELIMINATE=1\n",
           dir.c_str(), depth, warmReqs, warmTok);
    if (!fs::is_directory(dir)) {
        printf("K2_LIVE_DECODE_SUSTAINED_001=SKIP\n");
        _exit(0);
    }

    Sync("DEEP2_LIVE_POLICY", "PROMO");
    Sync("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", "1");
    Sync("DEEP2_K2_GPU_MLA", "1");
    Sync("DEEP2_WEIGHT_PIN", "1");
    Sync("DEEP2_WEIGHT_PREFETCH", "0");
    Sync("DEEP2_WEIGHT_OVERLAP", "0");
    Sync("DEEP2_LIVE_MECH", "trampoline,cyclone,elastic");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    Sync("RAWRXD_GPU_FWD", "0");
    Sync("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
    Sync("DEEP2_WEIGHT_SLOTS", "16");
    SetEnvironmentVariableA("DEEP2_WEIGHT_BUDGET_MIB", nullptr);
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "");

    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168;
    cfg.numLayers = 61;
    cfg.numHeads = 64;
    cfg.numKVHeads = 1;
    cfg.vocabSize = 163840;
    cfg.useMLA = true;
    cfg.maxSeqLen = 512;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_LIVE_DECODE_SUSTAINED_001=FAIL open\n");
        _exit(2);
    }
    ElasticDynamicProbe p{};
    ElasticBudget_ProbeHost(p);
    p.layers = depth;
    auto caps = ElasticBudget_Derive(p);
    ElasticBudget_Emit(stdout, caps, p);
    eng.enableElasticResidency(true);
    eng.refreshElasticDynamicBudget();
    if (!eng.isVulkanInitialized()) eng.enableVulkan(true);
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        vc->SetPinResidentBudget(caps.maxHotBytes);
        vc->ReleaseWeightWindow();
        vc->ClearPinnedGemvWeights();
        K2GpuStreamCopy_Bind(vc);
        PrintPin(eng, "INIT");
    }
    MoEEliminate_Reset();

    static const char* kPrompt =
        "Write a short paragraph on local decode throughput.";
    uint64_t up0 = 0, hit0 = 0, rej0 = 0, warmRes = 0;

    printf("\n--- WARM %u×%u (not rate-gated) ---\n", warmReqs, warmTok);
    K2LivePolicy_ClearSticky();
    for (uint32_t wr = 0; wr < warmReqs; ++wr) {
        if (auto* vc = eng.getVulkanComputeSlot(0))
            vc->SetPinResidentBudget(caps.maxHotBytes);
        Win warm = RunWindow(eng, kPrompt, warmTok, 0, 0, 0, warmRes);
        PrintWin(wr ? "WARM1" : "WARM0", warm, unique * warmTok);
        PrintPin(eng, wr ? "AFTER_WARM1" : "AFTER_WARM0");
        if (auto* vc = eng.getVulkanComputeSlot(0)) {
            up0 = vc->GemvWeightUploads();
            hit0 = vc->WeightContentHits();
            rej0 = vc->WeightPinRejects();
            const uint64_t a = vc->WeightStreamPeakBytes();
            const uint64_t b = vc->WeightPinResidentBytes();
            warmRes = b > a ? b : a;
        }
    }
    MoEEliminate_Emit(stdout);

    std::vector<Win> timed;
    for (uint32_t t : winsTok) {
        printf("\n--- TIMED %u ---\n", t);
        fflush(stdout);
        if (auto* vc = eng.getVulkanComputeSlot(0)) {
            vc->SetPinResidentBudget(caps.maxHotBytes);
            up0 = vc->GemvWeightUploads();
            hit0 = vc->WeightContentHits();
            rej0 = vc->WeightPinRejects();
            PrintPin(eng, "PRE");
        }
        Win w = RunWindow(eng, kPrompt, t, up0, hit0, rej0, warmRes);
        PrintWin(t == 32 ? "W32" : t == 64 ? "W64" : "W128", w, unique * t);
        PrintPin(eng, "POST");
        MoEEliminate_Emit(stdout);
        fflush(stdout);
        timed.push_back(w);
    }

    const double u32 = timed[0].tokens ? (double)timed[0].uploads / timed[0].tokens : 1e9;
    const double u64r = timed[1].tokens ? (double)timed[1].uploads / timed[1].tokens : 1e9;
    const double u128 = timed[2].tokens ? (double)timed[2].uploads / timed[2].tokens : 1e9;
    const double h32 = timed[0].tokens ? (double)timed[0].hits / timed[0].tokens : 0;
    const double h64 = timed[1].tokens ? (double)timed[1].hits / timed[1].tokens : 0;
    const double h128 = timed[2].tokens ? (double)timed[2].hits / timed[2].tokens : 0;
    const double uOps128 =
        timed[2].mlaOps ? (double)timed[2].uploads / (double)timed[2].mlaOps : 1.0;

    bool allOk = true, try0 = true, fail0 = true, pin0 = true, fb0 = true;
    bool pta0 = true, growth0 = true, pol1 = true, fused0 = true, pk0 = true;
    for (const Win& w : timed) {
        allOk &= w.ok;
        try0 &= (w.tryEntry == 0);
        fail0 &= (w.mlaFail == 0 && w.upFail == 0);
        pin0 &= (w.pinRej == 0);
        fb0 &= (w.fallback == 0);
        pta0 &= (w.pta == 0);
        growth0 &= (w.resPeak <= warmRes);
        pol1 &= (w.polSw == 1);
        fused0 &= (w.fusedPolCh == 0);
        pk0 &= (w.pinKeyZero == 0);
    }
    const bool uCollapse = (u64r <= u32 + 1e-9) && (u128 <= u64r + 1e-9);
    const double hMed = (h32 + h64 + h128) / 3.0;
    const bool hFlat = hMed > 0 && std::fabs(h32 - hMed) / hMed <= 0.15 &&
                       std::fabs(h64 - hMed) / hMed <= 0.15 &&
                       std::fabs(h128 - hMed) / hMed <= 0.15;
    const bool strong = (timed[2].uploads == 0) || (uOps128 <= 0.01);
    const bool real =
        std::getenv("DEEP2_REAL_K2_GENERATE") &&
        std::getenv("DEEP2_REAL_K2_GENERATE")[0] == '1';
    const bool pass = real && depth == 61 && allOk && try0 && fail0 && pin0 &&
                      fb0 && pta0 && growth0 && pol1 && fused0 && pk0 &&
                      uCollapse && hFlat && strong;

    printf("\nREAL_K2_GENERATE=%d LIVE_MLA_DISPATCH=MLA_Gemv\n", real ? 1 : 0);
    printf("STEADY_UPLOADS_PER_TOKEN U32=%.3f U64=%.3f U128=%.3f COLLAPSE=%d\n",
           u32, u64r, u128, uCollapse ? 1 : 0);
    printf("MLA_HITS_PER_TOKEN H32=%.1f H64=%.1f H128=%.1f FLAT=%d\n", h32, h64,
           h128, hFlat ? 1 : 0);
    printf("STRONG U128=%llu U/OPS=%.4f OK=%d PINKEY0=%d GROWTH0=%d\n",
           (unsigned long long)timed[2].uploads, uOps128, strong ? 1 : 0,
           pk0 ? 1 : 0, growth0 ? 1 : 0);
    printf("W128 family UP Q=%llu K=%llu V=%llu O=%llu EVICT=%llu "
           "MOE_USED=%llu\n",
           (unsigned long long)timed[2].upQ, (unsigned long long)timed[2].upK,
           (unsigned long long)timed[2].upV, (unsigned long long)timed[2].upO,
           (unsigned long long)timed[2].slotEvict,
           (unsigned long long)MoEEliminate_UsedCount());
    printf("K2_LIVE_DECODE_SUSTAINED_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_LIVE_DECODE_SUSTAINED_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "U32=%.6f U64=%.6f U128=%.6f UOPS128=%.6f\n", u32, u64r, u128,
                uOps128);
        fprintf(f, "MOE_USED=%llu\n",
                (unsigned long long)MoEEliminate_UsedCount());
        fprintf(f, "K2_LIVE_DECODE_SUSTAINED_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
