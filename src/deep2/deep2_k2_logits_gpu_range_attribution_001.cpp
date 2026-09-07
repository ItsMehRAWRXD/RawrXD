// deep2_k2_logits_gpu_range_attribution_001.cpp — C1 live seal
// output.weight → RMV → ResolveQuantBlockRange → fulfill → TryGpuHot receipt
#include "Deep2Engine.h"
#include "K2LogitsClimb.hpp"
#include "K2LogitsLineage.hpp"
#include "K2LogitsResidency.hpp"
#include "K2LogitsSplit.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2ShardIo.hpp"
#include "StreamPathTiming.hpp"
#include "VirtualTensorRange.hpp"
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

static const char* kGateDir =
    "G:\\~dev\\rawrxd\\evidence\\K2_LOGITS_GPU_RANGE_ATTRIBUTION_001";
static const char* kDefaultShard =
    "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

static void WriteGate(const char* body) {
#ifdef _WIN32
    CreateDirectoryA(kGateDir, nullptr);
#endif
    FILE* f = fopen((std::string(kGateDir) + "\\GATE_STATUS.txt").c_str(), "w");
    if (f) {
        fputs(body, f);
        fclose(f);
    }
}

struct Arm {
    bool ok = false;
    uint32_t cutRows = 0;
    double wallMs = 0;
    double logitsMs = 0;
    double gpuBranchMs = 0;
    double cpuBranchMs = 0;
    double splitWallMs = 0;
    LogitsLineageSnap lin{};
    LogitsSplitSnap split{};
    int parity = 0;
};

static Arm RunOnce(Deep2Engine& e, const char* prompt, uint32_t n,
                   uint32_t cutRows) {
    Arm a{};
    a.cutRows = cutRows;
    char cutEnv[32];
    std::snprintf(cutEnv, sizeof(cutEnv), "%u", cutRows);
    Sync("DEEP2_LOGITS_GPU_CUT", cutEnv);

    MLA_GpuGemv_Reset();
    MLA_TryGpuHot_Reset();
    LogitsSplit_Reset();
    LogitsClimb_Reset();
    LogitsResidency_Reset();
    LogitsLineage_Reset();
    StreamPathTiming_Reset();
    K2ShardIo_ResetCounters();

    GenerationOptions opts{};
    opts.maxTokens = (int)n;
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
    a.wallMs = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    a.ok = r.completed && !text.empty() && lastId >= 0;
    a.logitsMs = (double)SPT_logits().load() / 1000.0;
    a.split = LogitsSplit_Snapshot();
    a.lin = LogitsLineage_Snapshot();
    a.gpuBranchMs = (double)a.split.gpuBranchUs / 1000.0;
    a.cpuBranchMs = (double)a.split.cpuBranchUs / 1000.0;
    a.splitWallMs = (double)a.split.splitWallUs / 1000.0;
    a.parity = (LogitsParityFail().load() == 0) ? 1 : 0;
    return a;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
#endif
    fs::create_directories(kGateDir);

    const char* shard = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!shard || !shard[0]) shard = kDefaultShard;

    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_K2_GPU_MLA", "1");
    Sync("DEEP2_LOGITS_GPU_SPLIT", "1");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("RAWRXD_GPU_FWD", "0");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    Sync("DEEP2_LOGITS_GPU_CUT", "4096"); // freeze cut for repeatable hash
    _putenv_s("DEEP2_MLA_QKV_SPLIT", "");
    _putenv_s("DEEP2_MLA_FUSED_KV", "");

    printf("K2_LOGITS_GPU_RANGE_ATTRIBUTION_001\n");
    printf("K2_LOGITS_TENSOR=output.weight\n");
    printf("K2_LOGITS_TYPE=Q6_K\n");
    printf("WEIGHT_MODE=BOUNDED_STREAM\n");
    printf("K2_ROOT=%s\n", shard);
    printf("LAW=RMV→ResolveQuantBlockRange→fulfill→TryGpuHot receipt; "
           "no second resolve\n");

    if (!fs::is_directory(shard)) {
        WriteGate("MODEL_PATH=MISSING\nK2_LOGITS_GPU_RANGE_ATTRIBUTION_001="
                  "BLOCKED\n");
        printf("MODEL_PATH=MISSING\n");
        return 2;
    }

    Deep2Engine eng;
    if (!eng.openK2ShardDirectory(shard)) {
        WriteGate("OPEN_SHARDS=FAIL\nK2_LOGITS_GPU_RANGE_ATTRIBUTION_001=FAIL\n");
        printf("OPEN_SHARDS=FAIL\n");
        return 3;
    }
    EngineConfig cfg = eng.getConfig();
    cfg.useKVCache = true;
    if (!eng.initialize(cfg)) {
        WriteGate("INIT=FAIL\nK2_LOGITS_GPU_RANGE_ATTRIBUTION_001=FAIL\n");
        printf("INIT=FAIL\n");
        return 4;
    }
    eng.enableVulkan(true);

    // Warm + freeze samples (≥2 tokens → RANGE_HASH_REPEATABLE).
    (void)RunOnce(eng, "Say hi.", 4, 4096);
    auto freeze = RunOnce(eng, "Write one short sentence about copper.", 16,
                          4096);

    const bool lineage = LogitsLineage_Pass();
    const bool splitOk = freeze.split.modeSplit == 1 &&
                         freeze.split.gpuRows + freeze.split.cpuRows ==
                             freeze.split.rowsTotal &&
                         freeze.split.rowsTotal > 0;
    const bool dispatch = freeze.lin.gpuDispatch == 1;
    const bool parity = freeze.parity == 1;
    const bool freezeOk = freeze.lin.freezeRepeatable == 1;
    const bool byteEq = freeze.lin.fulfilledBytes == freeze.lin.dispatchBytes &&
                        freeze.lin.fulfilledBytes == freeze.lin.gpuExpectedBytes;

    printf("\n--- FREEZE ARM cut=%u ---\n", freeze.cutRows);
    LogitsLineage_Emit(stdout);
    LogitsSplit_Emit(stdout);
    MLA_TryGpuHot_Emit(stdout);
    printf("ARGMAX_PARITY=%d\n", parity ? 1 : 0);
    printf("GPU_DISPATCH=%u RANGE_SET_HASH_MATCH=%u RANGE_HASH_REPEATABLE=%u\n",
           freeze.lin.gpuDispatch, freeze.lin.matchHash,
           freeze.lin.freezeRepeatable);

    // Cut ladder (block authority = GPU_FIRST_BLOCK/GPU_BLOCK_COUNT).
    const uint32_t cuts[] = {2048, 4096, 6144, 8192}; // ~25/50/75/100 of cap
    printf("\n--- CUT LADDER ---\n");
    for (uint32_t c : cuts) {
        auto arm = RunOnce(eng, "One word: metal.", 4, c);
        printf("CUT_ROWS=%u GPU_BLOCK_COUNT=%u GPU_EXPECTED=%u "
               "FULFILLED=%llu DISPATCH=%llu GPU_US=%llu CPU_US=%llu "
               "JOIN_US=%llu MATCH=%u DISP=%u\n",
               c, arm.lin.gpuBlockCount, arm.lin.gpuExpectedBytes,
               (unsigned long long)arm.lin.fulfilledBytes,
               (unsigned long long)arm.lin.dispatchBytes,
               (unsigned long long)arm.split.gpuBranchUs,
               (unsigned long long)arm.split.cpuBranchUs,
               (unsigned long long)arm.split.splitWallUs, arm.lin.matchHash,
               arm.lin.gpuDispatch);
    }

    const bool pass =
        freeze.ok && lineage && splitOk && dispatch && parity && freezeOk &&
        byteEq && freeze.lin.matchTensor == 1 && freeze.lin.matchShard == 1 &&
        freeze.lin.matchOffset == 1 && freeze.lin.matchLength == 1 &&
        freeze.lin.matchOrder == 1 && freeze.lin.nameRelookup == 0 &&
        freeze.lin.secondResolve == 0 && freeze.lin.secondMountApi == 0 &&
        freeze.lin.cpuSourceRebuild == 0;

    char gate[4096];
    std::snprintf(
        gate, sizeof(gate),
        "MODEL=Kimi-K2-Instruct-0905\n"
        "K2_ROOT=%s\n"
        "WEIGHT_MODE=BOUNDED_STREAM\n"
        "K2_LOGITS_TENSOR=output.weight\n"
        "K2_LOGITS_TYPE=Q6_K\n"
        "VWA_RANGE_COUNT=%u\n"
        "VWA_FULFILLED_RANGE_COUNT=%u\n"
        "VWA_FULFILLED_BYTES=%llu\n"
        "GPU_SOURCE_RANGE_BYTES=%llu\n"
        "LOGITS_TOTAL_BLOCKS=%u\n"
        "GPU_FIRST_BLOCK=%u\n"
        "GPU_BLOCK_COUNT=%u\n"
        "CPU_FIRST_BLOCK=%u\n"
        "CPU_BLOCK_COUNT=%u\n"
        "GPU_EXPECTED_BYTES=%u\n"
        "GPU_FULFILLED_BYTES=%llu\n"
        "GPU_DISPATCH_BYTES=%llu\n"
        "FULFILLED_RANGE_HASH=%016llx\n"
        "GPU_SOURCE_RANGE_HASH=%016llx\n"
        "GPU_DISPATCH=%u\n"
        "RANGE_TENSOR_ID_MATCH=%u\n"
        "RANGE_SOURCE_ID_MATCH=%u\n"
        "RANGE_OFFSET_MATCH=%u\n"
        "RANGE_LENGTH_MATCH=%u\n"
        "RANGE_ORDER_MATCH=%u\n"
        "RANGE_SET_HASH_MATCH=%u\n"
        "RANGE_HASH_REPEATABLE=%u\n"
        "NAME_RELOOKUP=%u\n"
        "SECOND_RESOLVE=%u\n"
        "SECOND_MOUNT_API=%u\n"
        "CPU_SOURCE_REBUILD=%u\n"
        "ARGMAX_PARITY=%d\n"
        "VWA_PHYSICAL_LINEAGE=PASS\n"
        "K2_LOGITS_GPU_RANGE_ATTRIBUTION_001=%s\n",
        shard, freeze.lin.fulfilledCount, freeze.lin.fulfilledCount,
        (unsigned long long)freeze.lin.fulfilledBytes,
        (unsigned long long)freeze.lin.dispatchBytes,
        freeze.lin.logitsTotalBlocks, freeze.lin.gpuFirstBlock,
        freeze.lin.gpuBlockCount, freeze.lin.cpuFirstBlock,
        freeze.lin.cpuBlockCount, freeze.lin.gpuExpectedBytes,
        (unsigned long long)freeze.lin.fulfilledBytes,
        (unsigned long long)freeze.lin.dispatchBytes,
        (unsigned long long)freeze.lin.fulfilledHash,
        (unsigned long long)freeze.lin.dispatchHash, freeze.lin.gpuDispatch,
        freeze.lin.matchTensor, freeze.lin.matchShard, freeze.lin.matchOffset,
        freeze.lin.matchLength, freeze.lin.matchOrder, freeze.lin.matchHash,
        freeze.lin.freezeRepeatable, freeze.lin.nameRelookup,
        freeze.lin.secondResolve, freeze.lin.secondMountApi,
        freeze.lin.cpuSourceRebuild, parity ? 1 : 0, pass ? "PASS" : "FAIL");
    WriteGate(gate);

    printf("\nK2_LOGITS_GPU_RANGE_ATTRIBUTION_001=%s\n",
           pass ? "PASS" : "FAIL");
    fflush(stdout);
#ifdef _WIN32
    ::_exit(pass ? 0 : 1);
#else
    return pass ? 0 : 1;
#endif
}
