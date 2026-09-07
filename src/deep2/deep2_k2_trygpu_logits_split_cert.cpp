// deep2_k2_trygpu_logits_split_cert.cpp — K2_TRYGPU_LOGITS_SPLIT_001
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "ElasticDynamicBudget.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2LivePolicy.hpp"
#include "K2LogitsClimb.hpp"
#include "K2LogitsResidency.hpp"
#include "K2LogitsSplit.hpp"
#include "K2MLA_GpuGemv.hpp"
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

struct Win {
    bool ok = false;
    uint32_t tokens = 0;
    double wallMs = 0, logitsMs = 0;
    uint64_t tryEntry = 0, gemvEntry = 0;
    uint64_t q6Ops = 0, rangeOps = 0;
    uint64_t argmaxB = 0, rangeOutB = 0, fullRb = 0;
    uint64_t hotAlloc = 0;
    LogitsSplitSnap split{};
    LogitsClimbSnap climb{};
    int parity = 0;
};

static Win Run(Deep2Engine& e, const char* prompt, uint32_t n) {
    Win w{};
    w.tokens = n;
    MLA_GpuGemv_Reset();
    MLA_TryGpuHot_Reset();
    LogitsSplit_Reset();
    LogitsClimb_Reset();
    LogitsResidency_Reset();
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
    w.wallMs = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    w.ok = r.completed && !text.empty() && lastId >= 0;
    w.logitsMs = (double)SPT_logits().load() / 1000.0;
    w.tryEntry = MLA_TryGpuGemvEntries();
    w.gemvEntry = MLA_GemvEntries();
    w.q6Ops = MLA_Q6PackedOps();
    w.rangeOps = MLA_RangeArgmaxOps();
    w.argmaxB = MLA_GpuArgmaxBytes();
    w.rangeOutB = MLA_GpuRangeOutBytes();
    w.fullRb = MLA_GpuFullReadback();
    w.hotAlloc = LogitsHotAlloc().load();
    w.split = LogitsSplit_Snapshot();
    w.climb = LogitsClimb_Snapshot();
    w.parity = (LogitsParityFail().load() == 0) ? 1 : 0;
    return w;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
#endif
    const char* gate = "K2_TRYGPU_LOGITS_SPLIT_001";
    char evid[256];
    std::snprintf(evid, sizeof(evid), "G:\\~dev\\rawrxd\\evidence\\%s", gate);
    fs::create_directories(evid);

    Sync("DEEP2_K2_GPU_MLA", "1");
    Sync("DEEP2_LOGITS_GPU_SPLIT", "1");
    Sync("DEEP2_REAL_K2_GENERATE", "1");
    Sync("RAWRXD_GPU_FWD", "0");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    // Keep sealed QKV/KV defaults.
    _putenv_s("DEEP2_MLA_QKV_SPLIT", "");
    _putenv_s("DEEP2_MLA_FUSED_KV", "");

    const char* shard = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!shard || !shard[0]) {
        printf("%s=FAIL missing DEEP2_K2_SHARD_DIR\n", gate);
        return 1;
    }

    Deep2Engine eng;
    if (!eng.openK2ShardDirectory(shard)) {
        printf("%s=FAIL open shards\n", gate);
        return 1;
    }
    EngineConfig cfg = eng.getConfig();
    cfg.useKVCache = true;
    if (!eng.initialize(cfg)) {
        printf("%s=FAIL init\n", gate);
        return 1;
    }
    eng.enableVulkan(true);

    printf("%s\n", gate);
    printf("LAW=TryGpuHot Q6 RANGE_ARGMAX; CPU||GPU logits split; "
           "MLA_Gemv authority; no live TryGpu bypass\n");

    // Warm
    (void)Run(eng, "Say hi.", 8);
    auto w = Run(eng, "Write one short sentence about copper.", 32);

    const bool hot = w.tryEntry == 0 && w.gemvEntry > 0;
    const bool q6 = w.q6Ops > 0 && w.rangeOps > 0;
    const bool split = w.split.modeSplit == 1 &&
                       w.split.gpuRows + w.split.cpuRows == w.split.rowsTotal &&
                       w.split.rowsTotal > 0;
    const bool noFull = w.fullRb == 0 && w.climb.fullDequant == 0 &&
                        w.climb.fullMaterialize == 0;
    const bool argB = w.split.gpuArgmaxBytes > 0 &&
                      w.split.gpuArgmaxBytes <= 64;
    const bool seals = w.hotAlloc == 0 && w.parity == 1 && w.ok;
    const bool pass = hot && q6 && split && noFull && argB && seals;

    char path[300];
    std::snprintf(path, sizeof(path), "%s\\GATE_STATUS.txt", evid);
    if (FILE* f = std::fopen(path, "w")) {
        fprintf(f, "%s=%s\n", gate, pass ? "PASS" : "FAIL");
        fprintf(f, "TRYGPU_DIRECT_LIVE_ENTRY=%llu Q6_OPS=%llu RANGE=%llu\n",
                (unsigned long long)w.tryEntry, (unsigned long long)w.q6Ops,
                (unsigned long long)w.rangeOps);
        fprintf(f, "GPU_ROWS=%llu CPU_ROWS=%llu ARGMAX_BYTES=%llu\n",
                (unsigned long long)w.split.gpuRows,
                (unsigned long long)w.split.cpuRows,
                (unsigned long long)w.split.gpuArgmaxBytes);
        fclose(f);
    }

    MLA_TryGpuHot_Emit(stdout);
    LogitsSplit_Emit(stdout);
    printf("HOT_ALLOC=%llu SHARD_IO_MS_PER_TOKEN=%.3f\n",
           (unsigned long long)w.hotAlloc,
           w.tokens
               ? (double)(SPT_shardOpen().load() + SPT_shardRead().load()) /
                     1000.0 / w.tokens
               : 0.0);
    printf("LOGITS_MS_PER_TOKEN=%.3f\n",
           w.tokens ? w.logitsMs / w.tokens : 0.0);
    printf("ARGMAX_PARITY=%d\n", w.parity);
    printf("Q6_FULL_DEQUANT=%llu LOGITS_FULL_MATERIALIZE=%llu\n",
           (unsigned long long)w.climb.fullDequant,
           (unsigned long long)w.climb.fullMaterialize);
    printf("TRYGPU_HOTPATCH=%d LIVE_CALLER=MLA_Gemv "
           "TRYGPU_DIRECT_LIVE_ENTRY=%llu\n",
           hot ? 1 : 0, (unsigned long long)w.tryEntry);
    printf("PACKED_Q6_EXEC=%d LOGITS_MODE=%s\n", q6 ? 1 : 0,
           split ? "CPU_GPU_SPLIT" : "CPU_ONLY");
    printf("%s=%s\n", gate, pass ? "PASS" : "FAIL");
    fflush(stdout);
    // Skip CRT heap teardown (known Vulkan/static-pool interaction under split).
#ifdef _WIN32
    ::_exit(pass ? 0 : 1);
#else
    return pass ? 0 : 1;
#endif
}
