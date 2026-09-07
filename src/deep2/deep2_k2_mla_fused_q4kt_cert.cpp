// deep2_k2_mla_fused_q4kt_cert.cpp — K2_MLA_FUSED_Q4KT_001 (BATCH15 #04)
// Hot reuse BASE (packed GEMV) vs FUSED (MLA_FusedQ4KT). No new residency gate.
#include "Deep2Engine.h"
#include "ElasticDynamicBudget.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePolicy.hpp"
#include "K2MLA_FusedQ4KT.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "StreamPathTiming.hpp"
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
    double wallMs = 0, tps = 0;
    uint64_t mlaOps = 0, mlaFail = 0, up = 0, hit = 0, pinRej = 0;
    uint64_t fusedCalls = 0, fusedOps = 0, fusedFail = 0, fusedUs = 0;
    uint64_t compatUs = 0, f32Exp = 0, tempB = 0, mlaUs = 0, hotMiB = 0;
};

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

static void ArmEnv(uint32_t depth, bool fused) {
    Sync("DEEP2_LIVE_POLICY", "PROMO");
    Sync("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", "1");
    Sync("DEEP2_K2_GPU_MLA", "1");
    Sync("DEEP2_WEIGHT_PIN", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_WEIGHT_SLOTS", "16");
    Sync("DEEP2_MLA_GPU_Q4_ONLY", "1");
    Sync("DEEP2_LIVE_MECH", "none");
    Sync("DEEP2_GEN_ALG", "standard");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    Sync("DEEP2_MLA_FUSED_Q4KT", fused ? "1" : "0");
    char b[16];
    std::snprintf(b, sizeof(b), "%u", depth);
    Sync("RAWRXD_K2_LAYERS", b);
    SetEnvironmentVariableA("DEEP2_WEIGHT_BUDGET_MIB", nullptr);
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "");
}

static void BindHot(Deep2Engine& e, uint32_t depth) {
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

static Arm Timed(Deep2Engine& e, const char* prompt, uint32_t depth,
                 uint32_t tokens, bool fused) {
    Arm a{};
    ArmEnv(depth, fused);
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    StreamPathTiming_Reset();
    const uint64_t up0 =
        e.getVulkanComputeSlot(0) ? e.getVulkanComputeSlot(0)->GemvWeightUploads()
                                  : 0;
    const uint64_t hit0 =
        e.getVulkanComputeSlot(0)
            ? e.getVulkanComputeSlot(0)->WeightContentHits()
            : 0;
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
    a.tps = (r.ok && tokens && a.wallMs > 0) ? (1000.0 * tokens / a.wallMs) : 0;
    a.mlaOps = MLA_GpuGemvOps();
    a.mlaFail = MLA_GpuGemvFail();
    a.fusedCalls = MLA_FusedQ4KT_Calls();
    a.fusedOps = MLA_FusedQ4KT_Ops();
    a.fusedFail = MLA_FusedQ4KT_Fail();
    a.fusedUs = MLA_FusedQ4KT_Us();
    a.compatUs = MLA_GemvCompatUs();
    a.f32Exp = MLA_F32WeightExpands();
    a.tempB = MLA_Q4KTempWeightBytes();
    a.mlaUs = SPT_mla().load();
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        a.up = vc->GemvWeightUploads() - up0;
        a.hit = vc->WeightContentHits() - hit0;
        a.pinRej = vc->WeightPinRejects();
        a.hotMiB = vc->WeightBudgetBytes() >> 20;
    }
    return a;
}

static void PrintArm(const char* tag, const Arm& a, uint64_t expect) {
    printf("%s ok=%d tps=%.1f wall=%.0f mla=%llu fail=%llu u=%llu h=%llu "
           "pinRej=%llu hot=%llu\n",
           tag, a.ok ? 1 : 0, a.tps, a.wallMs, (unsigned long long)a.mlaOps,
           (unsigned long long)a.mlaFail, (unsigned long long)a.up,
           (unsigned long long)a.hit, (unsigned long long)a.pinRej,
           (unsigned long long)a.hotMiB);
    printf("  FUSED calls=%llu ops=%llu fail=%llu us=%llu expect=%llu\n",
           (unsigned long long)a.fusedCalls, (unsigned long long)a.fusedOps,
           (unsigned long long)a.fusedFail, (unsigned long long)a.fusedUs,
           (unsigned long long)expect);
    printf("  COMPAT_US=%llu MLA_COMPUTE_US=%llu F32_EXP=%llu TEMP_B=%llu\n",
           (unsigned long long)a.compatUs, (unsigned long long)a.mlaUs,
           (unsigned long long)a.f32Exp, (unsigned long long)a.tempB);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_MLA_FUSED_Q4KT_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    Sync("DEEP2_K2_SHARD_DIR", dir.c_str());
    const uint32_t nTok = 4, depth = 61;
    const uint64_t expect = 3ull * depth * nTok;
    printf("K2_MLA_FUSED_Q4KT_001\nAUTHORITY=MLA_Gemv→MLA_FusedQ4KT\n"
           "MODEL=%s D=%u T=%u expectOps=%llu\n",
           dir.c_str(), depth, nTok, (unsigned long long)expect);
    if (!fs::is_directory(dir)) {
        printf("K2_MLA_FUSED_Q4KT_001=SKIP\n");
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
        printf("K2_MLA_FUSED_Q4KT_001=FAIL open\n");
        _exit(2);
    }

    static const char* kPrompt =
        "Write one short paragraph on local decode tok/s.";
    printf("--- warm (populate pins, BASE path) ---\n");
    ArmEnv(depth, false);
    BindHot(eng, depth);
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        vc->ReleaseWeightWindow();
        vc->ClearPinnedGemvWeights();
    }
    MLA_GpuGemv_Reset();
    {
        K2NativeStreamGate::Config kc;
        kc.prompt = kPrompt;
        kc.streamTokens = nTok;
        kc.layerDepth = depth;
        kc.enableMlaComplete = true;
        (void)eng.runK2NativeStreamPartial(kc);
    }
    uint64_t warmUp = 0, warmHit = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        warmUp = vc->GemvWeightUploads();
        warmHit = vc->WeightContentHits();
    }
    printf("WARM uploads=%llu hits=%llu mla=%llu\n",
           (unsigned long long)warmUp, (unsigned long long)warmHit,
           (unsigned long long)MLA_GpuGemvOps());

    printf("--- BASE timed (packed GEMV, keep pins) ---\n");
    Arm base = Timed(eng, kPrompt, depth, nTok, false);
    PrintArm("BASE", base, expect);

    printf("--- FUSED timed (MLA_FusedQ4KT, keep pins) ---\n");
    Arm fused = Timed(eng, kPrompt, depth, nTok, true);
    PrintArm("FUSED", fused, expect);

    const bool reuseOk = base.up == 0 && fused.up == 0 && base.hit > 0 &&
                         fused.hit > 0 && warmUp > 0;
    const bool baseOk = base.ok && base.mlaFail == 0 && base.mlaOps >= expect &&
                        base.fusedOps == 0 && base.f32Exp == 0;
    const bool fusedOk =
        fused.ok && fused.mlaFail == 0 && fused.fusedFail == 0 &&
        fused.fusedCalls > 0 && fused.fusedOps == expect && fused.f32Exp == 0 &&
        fused.tempB == 0 && fused.mlaOps >= expect;
    // Compute win: fused US must beat base compat US (same hot residency).
    const uint64_t baseUs =
        base.compatUs ? base.compatUs : (base.mlaUs ? base.mlaUs : 1);
    const uint64_t fusedUs =
        fused.fusedUs ? fused.fusedUs : (fused.mlaUs ? fused.mlaUs : 0);
    const bool faster = fusedUs > 0 && fusedUs < baseUs;
    const bool pass = reuseOk && baseOk && fusedOk && faster && !base.pinRej &&
                      !fused.pinRej;

    printf("COMPARE baseUs=%llu fusedUs=%llu delta=%lld faster=%d\n",
           (unsigned long long)baseUs, (unsigned long long)fusedUs,
           (long long)baseUs - (long long)fusedUs, faster ? 1 : 0);
    printf("REUSE u0=%d F32_EXP=%llu TEMP_B=%llu\n", reuseOk ? 1 : 0,
           (unsigned long long)fused.f32Exp, (unsigned long long)fused.tempB);
    printf("K2_MLA_FUSED_Q4KT_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_MLA_FUSED_Q4KT_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f,
                "BASE_US=%llu FUSED_US=%llu uB=%llu uF=%llu hB=%llu hF=%llu "
                "fOps=%llu f32=%llu faster=%d\n",
                (unsigned long long)baseUs, (unsigned long long)fusedUs,
                (unsigned long long)base.up, (unsigned long long)fused.up,
                (unsigned long long)base.hit, (unsigned long long)fused.hit,
                (unsigned long long)fused.fusedOps,
                (unsigned long long)fused.f32Exp, faster ? 1 : 0);
        fprintf(f, "K2_MLA_FUSED_Q4KT_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    FILE* s = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_MLA_FUSED_Q4KT_001\\SUMMARY.txt", "w");
    if (s) {
        fprintf(s,
                "K2_MLA_FUSED_Q4KT_001=%s\n"
                "AUTHORITY=MLA_Gemv→MLA_FusedQ4KT (compat=DispatchGEMVPacked)\n"
                "WARM u=%llu h=%llu\n"
                "BASE  u=%llu h=%llu compatUs=%llu\n"
                "FUSED u=%llu h=%llu fusedUs=%llu ops=%llu f32=%llu tempB=%llu\n"
                "FASTER=%d (fusedUs < baseUs)\n",
                pass ? "PASS" : "FAIL", (unsigned long long)warmUp,
                (unsigned long long)warmHit, (unsigned long long)base.up,
                (unsigned long long)base.hit, (unsigned long long)baseUs,
                (unsigned long long)fused.up, (unsigned long long)fused.hit,
                (unsigned long long)fusedUs, (unsigned long long)fused.fusedOps,
                (unsigned long long)fused.f32Exp, (unsigned long long)fused.tempB,
                faster ? 1 : 0);
        fclose(s);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
