// deep2_k2_braid_transient_exec_cert.cpp — BRAID_TRANSIENT_EXEC_001
// Certify that braid execution policy operates as a transient layer above
// packed GEMV — no source rewrites, no FP32 warehouse, no unsupported
// reinterpret, direct packed kernel owns compute.
//
// PASS iff:
//   SOURCE_REWRITE_BYTES        = 0
//   HOST_F32_WAREHOUSE_BYTES    = 0
//   UNSUPPORTED_FORMAT_REINTERPRET = 0
//   DIRECT_PACKED > 0
//   PLANS_ISSUED > 0
//   every executed tensor preserves original storage type
//   semantic role is known
//   direct packed kernel owns compute
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "K2BraidExecutionPolicy.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "K2LogitsResidency.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2MlaStageTiming.hpp"
#include "K2ShardIo.hpp"
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
    bool ok = false;
    uint32_t tokens = 0;
    uint64_t mlaUs = 0, logitsUs = 0, shardAttnUs = 0, hostCopyUs = 0;
    uint64_t fb = 0, tryExt = 0, attnShard = 0, q6Hit = 0, hotAlloc = 0;
    uint32_t cacheEntries = 0;
    // Braid witness snapshot (tightened chain)
    K2BraidWitnessSnapshot w{};
};

static Arm Run(Deep2Engine& e, const char* prompt, uint32_t tok) {
    Arm a{};
    a.tokens = tok;
    MLA_GpuGemv_Reset();
    WeightResolve_Reset();
    LogitsResidency_Reset();
    MlaStage_Reset();
    StreamPathTiming_Reset();
    StreamTransfer_Reset();
    K2GpuStreamCopy_Reset();
    K2Braid_ResetWitnesses();

    GenerationOptions opts{};
    opts.maxTokens = (int)tok;
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
    a.mlaUs = SPT_mla().load();
    a.logitsUs = SPT_logits().load();
    a.shardAttnUs = SPT_shardAttn().load();
    a.hostCopyUs = SPT_hostCopy().load();
    a.tryExt = MLA_TryGpuGemvEntries();
    a.fb = LivePath_Counters().fallbackCount + e.vulkanGemvFallbackCount();
    a.attnShard = AttnResolveShard();
    a.q6Hit = LogitsPackedResidentHits().load();
    a.hotAlloc = LogitsHotAlloc().load();
    a.cacheEntries = K2LiveCache_Entries();

    a.w = K2Braid_GetWitnessSnapshot();
    return a;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("DEEP2_TPS_DISPLAY_SCALE", "1");
    Sync("DEEP2_MOE_ELIMINATE_UNUSED", "1");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", "0");
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
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\BRAID_TRANSIENT_EXEC_001", nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    const uint32_t depth = 61, warmTok = 8, timedTok = 8;
    printf("BRAID_TRANSIENT_EXEC_001\nMODEL=%s DEPTH=%u\n", dir.c_str(), depth);
    printf("LAW=braid=transient exec policy; no source rewrite, no F32 warehouse\n");
    if (!fs::is_directory(dir)) {
        printf("BRAID_TRANSIENT_EXEC_001=SKIP\n");
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
    cfg.maxSeqLen = 256;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("BRAID_TRANSIENT_EXEC_001=FAIL open\n");
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
    }
    MoEEliminate_Reset();
    K2LiveCache_Reset((std::max)(caps.maxHotBytes, 12288ull << 20));
    K2LivePolicy_ClearSticky();

    static const char* kPrompt =
        "Write one short sentence about local decode throughput.";

    printf("\n--- WARM ---\n");
    Arm warm = Run(eng, kPrompt, warmTok);
    printf("WARM ok=%d cacheN=%u\n", warm.ok ? 1 : 0, warm.cacheEntries);
    K2LiveCache_MarkWarm();

    printf("\n--- TIMED ---\n");
    Arm timed = Run(eng, kPrompt, timedTok);
    MlaStage_Emit(stdout);
    K2Braid_EmitCounters(stdout);

    // ------------------------------------------------------------------------
    // Tightened aggregate predicate — proves real packed execution, not just
    // that the policy object was called.
    // ------------------------------------------------------------------------
    const K2BraidWitnessSnapshot& w = timed.w;

    bool rolesConsistent = true;
    uint64_t rolePlanTotal = 0, roleExecTotal = 0, rolePackedTotal = 0;
    for (uint32_t i = 0; i < K2_BRAID_ROLE_SLOTS; ++i) {
        rolePlanTotal += w.rolePlans[i];
        roleExecTotal += w.roleExecs[i];
        rolePackedTotal += w.rolePackedExecs[i];
        if (w.roleExecs[i] > w.rolePlans[i]) rolesConsistent = false;
        if (w.rolePackedExecs[i] > w.roleExecs[i]) rolesConsistent = false;
    }

    const bool liveAuthority = w.mlaGemvEntries > 0;
    const bool everyMlaWasPlanned = w.planCount == w.mlaGemvEntries;
    const bool everyPlanExecuted = w.execCount == w.planCount;
    const bool packedActuallyRan = w.packedExecCount > 0;
    const bool roleAccounting =
        rolesConsistent &&
        rolePlanTotal == w.planCount &&
        roleExecTotal == w.execCount &&
        rolePackedTotal == w.packedExecCount;
    const bool transientOnly = w.persistedBraidBytes == 0;
    const bool noSourceRewrite = w.sourceRewriteBytes == 0;
    const bool noF32Warehouse = w.f32WarehouseBytes == 0;
    const bool noIllegalReinterpret = w.unsupportedReinterpret == 0;

    // Gate pass criteria (freeze seals)
    const bool freeze =
        timed.ok && warm.ok &&
        timed.shardAttnUs == 0 && timed.attnShard == 0 &&
        timed.hostCopyUs == 0 &&
        timed.fb == 0 && timed.tryExt == 0 &&
        timed.cacheEntries >= 551 && timed.q6Hit > 0 &&
        timed.hotAlloc == 0;

    const bool pass =
        freeze && depth == 61 &&
        liveAuthority &&
        everyMlaWasPlanned &&
        everyPlanExecuted &&
        packedActuallyRan &&
        roleAccounting &&
        transientOnly &&
        noSourceRewrite &&
        noF32Warehouse &&
        noIllegalReinterpret;

    printf("BRAID_MLA=%llu\n", (unsigned long long)w.mlaGemvEntries);
    printf("BRAID_PLAN=%llu\n", (unsigned long long)w.planCount);
    printf("BRAID_EXEC=%llu\n", (unsigned long long)w.execCount);
    printf("BRAID_PACKED_EXEC=%llu\n", (unsigned long long)w.packedExecCount);
    printf("SOURCE_REWRITE_BYTES=%llu\n", (unsigned long long)w.sourceRewriteBytes);
    printf("F32_WAREHOUSE_BYTES=%llu\n", (unsigned long long)w.f32WarehouseBytes);
    printf("UNSUPPORTED_REINTERPRET=%llu\n", (unsigned long long)w.unsupportedReinterpret);
    printf("BRAID_PERSISTED_BYTES=%llu\n", (unsigned long long)w.persistedBraidBytes);
    printf("TIMED MLA_US=%llu LOGITS_US=%llu\n",
           (unsigned long long)timed.mlaUs, (unsigned long long)timed.logitsUs);
    printf("FREEZE_OK=%d LIVE_AUTH=%d PLAN_ALL=%d EXEC_ALL=%d PACKED_RAN=%d "
           "ROLE_ACC=%d TRANSIENT=%d NO_REWRITE=%d NO_F32=%d NO_REINTERPRET=%d\n",
           freeze ? 1 : 0, liveAuthority ? 1 : 0, everyMlaWasPlanned ? 1 : 0,
           everyPlanExecuted ? 1 : 0, packedActuallyRan ? 1 : 0,
           roleAccounting ? 1 : 0, transientOnly ? 1 : 0,
           noSourceRewrite ? 1 : 0, noF32Warehouse ? 1 : 0,
           noIllegalReinterpret ? 1 : 0);
    printf("NEXT_CLIMB=K2_MLA_FABRIC_RESIDENCY_001\n");
    printf("BRAID_TRANSIENT_EXEC_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\BRAID_TRANSIENT_EXEC_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f,
            "BRAID_MLA=%llu BRAID_PLAN=%llu BRAID_EXEC=%llu BRAID_PACKED_EXEC=%llu\n"
            "SOURCE_REWRITE_BYTES=%llu F32_WAREHOUSE_BYTES=%llu\n"
            "UNSUPPORTED_REINTERPRET=%llu BRAID_PERSISTED_BYTES=%llu\n"
            "BRAID_TRANSIENT_EXEC_001=%s\n",
            (unsigned long long)w.mlaGemvEntries,
            (unsigned long long)w.planCount,
            (unsigned long long)w.execCount,
            (unsigned long long)w.packedExecCount,
            (unsigned long long)w.sourceRewriteBytes,
            (unsigned long long)w.f32WarehouseBytes,
            (unsigned long long)w.unsupportedReinterpret,
            (unsigned long long)w.persistedBraidBytes,
            pass ? "PASS" : "FAIL");
        fclose(f);
    }

    fflush(stdout);
    _exit(pass ? 0 : 2);
}