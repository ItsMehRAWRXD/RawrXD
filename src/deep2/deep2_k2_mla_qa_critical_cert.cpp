// deep2_k2_mla_qa_critical_cert.cpp — K2_MLA_QA_CRITICAL_001
// A/B/C q_a path under frozen SPLIT_KV. q_b / host KV / expand / logits frozen.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "K2LogitsResidency.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2MLA_QaCritical.hpp"
#include "K2MlaStageTiming.hpp"
#include "K2WeightResolve.hpp"
#include "MoEEliminate.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include "vulkan_compute.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

struct Arm {
    const char* name = "";
    bool ok = false;
    int32_t lastTok = -1;
    uint64_t qaStage = 0, qbStage = 0, kvaStage = 0, qkv = 0, mla = 0;
    uint64_t qaTotal = 0, qaFused = 0, qaCompat = 0, qaDisp = 0, qaKern = 0;
    uint64_t qaOut = 0, qaCalls = 0, qaFHit = 0, qaCHit = 0, qaFb = 0, qaUp = 0;
    uint64_t up = 0, hit = 0, gemvFail = 0, hotAlloc = 0;
    uint64_t parityFail = 0, parityChk = 0, cacheN = 0, ops = 0;
};

static Arm Run(Deep2Engine& e, const char* prompt, uint32_t tok,
               const char* path, uint64_t up0, uint64_t hit0) {
    Arm a{};
    a.name = path;
    Sync("DEEP2_MLA_QA_PATH", path);
    MLA_GpuGemv_Reset();
    WeightResolve_Reset();
    LogitsResidency_Reset();
    MlaStage_Reset();
    StreamPathTiming_Reset();
    StreamTransfer_Reset();
    GenerationOptions opts{};
    opts.maxTokens = tok;
    opts.temperature = 0.0f;
    opts.topK = 1;
    std::string text;
    int32_t last = -1;
    auto r = e.generateStream(prompt, opts,
                              [&](int32_t id, const std::string& t) -> bool {
                                  last = id;
                                  text += t;
                                  return true;
                              });
    a.ok = r.completed && !text.empty() && last >= 0;
    a.lastTok = last;
    a.qaStage = MlaStage_QaUs().load();
    a.qbStage = MlaStage_QbUs().load();
    a.kvaStage = MlaStage_KvaUs().load();
    a.qkv = MlaStage_QkvUs().load();
    a.mla = SPT_mla().load();
    a.qaTotal = MLA_QaTotalUs();
    a.qaFused = MLA_QaFusedUs();
    a.qaCompat = MLA_QaCompatUs();
    a.qaDisp = MLA_QaDispatchUs();
    a.qaKern = MLA_QaKernelUs();
    a.qaOut = MLA_QaOutputUs();
    a.qaCalls = MLA_QaCalls();
    a.qaFHit = MLA_QaFusedHits();
    a.qaCHit = MLA_QaCompatHits();
    a.qaFb = MLA_QaFallbacks();
    a.qaUp = MLA_QaUploads();
    a.gemvFail = MLA_GpuGemvFail();
    a.ops = MLA_GpuGemvOps();
    a.hotAlloc = LogitsHotAlloc().load();
    a.parityFail = LogitsParityFail().load();
    a.parityChk = LogitsParityChecks().load();
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        a.up = vc->GemvWeightUploads() - up0;
        a.hit = vc->WeightContentHits() - hit0;
    }
    a.cacheN = K2LiveCache_Entries();
    return a;
}

static void PrintArm(const Arm& a) {
    printf("--- ARM %s ---\n", a.name);
    printf("ok=%d tok=%d qkv=%llu qa_stage=%llu qb=%llu kva=%llu mla=%llu\n",
           a.ok ? 1 : 0, a.lastTok, (unsigned long long)a.qkv,
           (unsigned long long)a.qaStage, (unsigned long long)a.qbStage,
           (unsigned long long)a.kvaStage, (unsigned long long)a.mla);
    MLA_QaCrit_Emit(stdout);
    printf("up=%llu hit=%llu ops=%llu fail=%llu fb=%llu cacheN=%llu "
           "parity=%llu/%llu hot=%llu\n",
           (unsigned long long)a.up, (unsigned long long)a.hit,
           (unsigned long long)a.ops, (unsigned long long)a.gemvFail,
           (unsigned long long)a.qaFb, (unsigned long long)a.cacheN,
           (unsigned long long)a.parityFail, (unsigned long long)a.parityChk,
           (unsigned long long)a.hotAlloc);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_MLA_QA_CRITICAL_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    printf("K2_MLA_QA_CRITICAL_001\n");
    printf("LAW=SPLIT_KV frozen; A/B/C q_a fused vs packed only\n");
    if (!fs::is_directory(dir)) {
        printf("K2_MLA_QA_CRITICAL_001=SKIP\n");
        _exit(0);
    }

    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_MOE_ELIMINATE_UNUSED", "1");
    Sync("DEEP2_LIVE_POLICY", "PROMO");
    Sync("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_MLA_QKV_SPLIT", "1"); // sealed champion
    Sync("DEEP2_K2_GPU_STREAM_COPY", "1");
    Sync("DEEP2_K2_GPU_MLA", "1");
    Sync("DEEP2_WEIGHT_PIN", "1");
    Sync("DEEP2_WEIGHT_PREFETCH", "0");
    Sync("DEEP2_LIVE_MECH", "trampoline,cyclone,elastic");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    Sync("RAWRXD_GPU_FWD", "0");
    Sync("RAWRXD_K2_LAYERS", "61");
    Sync("DEEP2_WEIGHT_SLOTS", "16");
    SetEnvironmentVariableA("DEEP2_WEIGHT_BUDGET_MIB", nullptr);
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "");
    SetEnvironmentVariableA("DEEP2_MLA_FUSED_KV", nullptr);
    _putenv_s("DEEP2_MLA_FUSED_KV", "");

    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168;
    cfg.numLayers = 61;
    cfg.numHeads = 64;
    cfg.numKVHeads = 1;
    cfg.vocabSize = 163840;
    cfg.useMLA = true;
    cfg.maxSeqLen = 256;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_MLA_QA_CRITICAL_001=FAIL open\n");
        _exit(2);
    }
    ElasticDynamicProbe p{};
    ElasticBudget_ProbeHost(p);
    p.layers = 61;
    auto caps = ElasticBudget_Derive(p);
    eng.enableElasticResidency(true);
    eng.refreshElasticDynamicBudget();
    if (!eng.isVulkanInitialized()) eng.enableVulkan(true);
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        vc->SetPinResidentBudget(caps.maxHotBytes);
        vc->ReleaseWeightWindow();
        vc->ClearPinnedGemvWeights();
        K2GpuStreamCopy_Bind(vc);
    }
    MoEEliminate_Reset();
    K2LiveCache_Reset((std::max)(caps.maxHotBytes, 12288ull << 20));
    static const char* kPrompt =
        "Write one short sentence about local decode throughput.";
    K2LivePolicy_ClearSticky();

    const uint32_t nTok = 8;
    const uint64_t expectQa = 61ull * nTok;

    printf("\n--- WARM ---\n");
    Sync("DEEP2_MLA_QA_PATH", "auto");
    Arm warm = Run(eng, kPrompt, 8, "auto", 0, 0);
    printf("WARM ok=%d cacheN=%llu tok=%d qa_calls=%llu\n", warm.ok ? 1 : 0,
           (unsigned long long)warm.cacheN, warm.lastTok,
           (unsigned long long)warm.qaCalls);
    K2LiveCache_MarkWarm();

    uint64_t up0 = 0, hit0 = 0;
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }

    Arm A = Run(eng, kPrompt, nTok, "auto", up0, hit0);
    PrintArm(A);
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }
    Arm B = Run(eng, kPrompt, nTok, "fused", up0, hit0);
    PrintArm(B);
    if (auto* vc = eng.getVulkanComputeSlot(0)) {
        up0 = vc->GemvWeightUploads();
        hit0 = vc->WeightContentHits();
    }
    Arm C = Run(eng, kPrompt, nTok, "compat", up0, hit0);
    PrintArm(C);

    const uint64_t expectOps = 3ull * 61ull * nTok; // qa+qb+o under SPLIT_KV
    const bool freeze =
        A.ops == expectOps && B.ops == expectOps && C.ops == expectOps &&
        A.up == 0 && B.up == 0 && C.up == 0 &&
        A.qaUp == 0 && B.qaUp == 0 && C.qaUp == 0 &&
        A.gemvFail == 0 && B.gemvFail == 0 && C.gemvFail == 0 &&
        A.qaFb == 0 && B.qaFb == 0 && C.qaFb == 0 &&
        A.hotAlloc == 0 && B.hotAlloc == 0 && C.hotAlloc == 0 &&
        A.parityFail == 0 && B.parityFail == 0 && C.parityFail == 0 &&
        A.parityChk > 0 && A.ok && B.ok && C.ok &&
        A.lastTok == B.lastTok && B.lastTok == C.lastTok &&
        A.qaCalls >= expectQa && B.qaCalls >= expectQa &&
        C.qaCalls >= expectQa;

    // Path truth: fused arm should land fused hits; compat should not.
    const bool pathOk =
        B.qaFHit >= expectQa && B.qaCHit == 0 &&
        C.qaFHit == 0 && C.qaCHit >= expectQa &&
        A.qaFHit + A.qaCHit >= expectQa;

    const uint64_t aUs = A.qaTotal ? A.qaTotal : A.qaStage;
    const uint64_t bUs = B.qaTotal ? B.qaTotal : B.qaStage;
    const uint64_t cUs = C.qaTotal ? C.qaTotal : C.qaStage;

    const char* winner = "SIMILAR";
    {
        const uint64_t lo = (bUs < cUs) ? bUs : cUs;
        const uint64_t hi = (bUs < cUs) ? cUs : bUs;
        if (hi && lo * 100ull >= hi * 98ull)
            winner = "SIMILAR";
        else if (bUs < cUs)
            winner = "FUSED";
        else
            winner = "PACKED";
    }
    const bool pass = freeze && pathOk;
    printf("\nCOMPARE A=%llu B_fused=%llu C_packed=%llu winner=%s\n",
           (unsigned long long)aUs, (unsigned long long)bUs,
           (unsigned long long)cUs, winner);
    printf("FREEZE_OK=%d PATH_OK=%d TOK=%d\n", freeze ? 1 : 0, pathOk ? 1 : 0,
           A.lastTok);
    printf("NEXT=%s\n",
           !strcmp(winner, "FUSED")
               ? "descend_MLA_FusedQ4KT_q_a"
               : !strcmp(winner, "PACKED")
                     ? "stop_fused_for_q_a"
                     : "inspect_qa_norm_or_qa_qb_handoff");
    printf("K2_MLA_QA_CRITICAL_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_MLA_QA_CRITICAL_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f,
                "A_US=%llu B_FUSED_US=%llu C_PACKED_US=%llu WINNER=%s\n"
                "FREEZE_OK=%d PATH_OK=%d SPLIT_KV=1 OPS=%llu "
                "(expect 3*61*T)\n"
                "QA_FUSED_HITS_B=%llu QA_COMPAT_HITS_C=%llu\n"
                "ARGMAX_TOK=%d PARITY_FAIL=%llu\n"
                "K2_MLA_QA_CRITICAL_001=%s\n",
                (unsigned long long)aUs, (unsigned long long)bUs,
                (unsigned long long)cUs, winner, freeze ? 1 : 0, pathOk ? 1 : 0,
                (unsigned long long)A.ops, (unsigned long long)B.qaFHit,
                (unsigned long long)C.qaCHit, A.lastTok,
                (unsigned long long)A.parityFail, pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
