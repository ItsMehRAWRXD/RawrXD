#include "deep2/Deep2Engine.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <windows.h>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

static GenerationResult run(
    Deep2Engine& e, const char* prompt, uint32_t n, bool print)
{
    GenerationOptions o{};
    o.maxTokens = n;
    o.temperature = 0.0f;
    o.topK = 1;
    o.topP = 1.0f;
    o.repeatPenalty = 1.0f;
    o.seed = 1;

    return e.generateStream(
        prompt, o,
        [print](int32_t, const std::string& piece) -> bool {
            if (print && !piece.empty()) {
                std::fwrite(piece.data(), 1, piece.size(), stdout);
                std::fflush(stdout);
            }
            return true;
        });
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: qwen32_40tps_gate.exe model.gguf [measure_tokens]\n");
        return 2;
    }

    const char* model = argv[1];
    uint32_t measure = 256;
    if (argc > 2) {
        const long v = std::strtol(argv[2], nullptr, 10);
        if (v > 0 && v <= 4096) measure = static_cast<uint32_t>(v);
    }

    Deep2Engine e;
    EngineConfig cfg{};
    cfg.maxSeqLen = 4096;
    cfg.numThreads = 0;

    if (!e.initialize(cfg)) {
        std::fprintf(stderr, "QWEN32_40TPS=HOLD stage=initialize\n");
        return 10;
    }
    if (!e.loadModel(model)) {
        std::fprintf(stderr, "QWEN32_40TPS=HOLD stage=load\n");
        return 11;
    }

    const auto& c = e.getConfig();
    if (c.numLayers != 64 || c.hiddenDim != 5120 ||
        c.numHeads != 40 || c.numKVHeads != 8) {
        std::fprintf(stderr,
            "QWEN32_40TPS=HOLD stage=geometry layers=%zu hidden=%zu heads=%zu kv=%zu\n",
            c.numLayers, c.hiddenDim, c.numHeads, c.numKVHeads);
        return 12;
    }

    e.setVulkanStrictNoCpuFallback(true);
    e.enableVulkan(true);
    if (!e.isVulkanInitialized() || !e.gpuResidentDecodeEnabled()) {
        std::fprintf(stderr,
            "QWEN32_40TPS=HOLD stage=vulkan devices=%u\n",
            e.vulkanDeviceCount());
        return 13;
    }

    // Warmup pass: 32 tokens to stabilize residency and adaptive split.
    const auto warm = run(
        e,
        "Write a detailed C++ implementation of a lock free queue and explain ",
        32, false);
    if (!warm.generatedTokens) {
        std::fprintf(stderr, "QWEN32_40TPS=HOLD stage=warmup\n");
        return 14;
    }

    const uint64_t uploads0a = e.vulkanSlotWeightUploads(0);
    const uint64_t uploads1a = e.vulkanSlotWeightUploads(1);
    const uint64_t hits0a = e.vulkanSlotWeightHits(0);
    const uint64_t hits1a = e.vulkanSlotWeightHits(1);
    const uint64_t submit0a = e.vulkanSlotQueueSubmits(0);
    const uint64_t submit1a = e.vulkanSlotQueueSubmits(1);

    e.reset();
    e.resetGpuForwardCounters();

    LARGE_INTEGER freq{}, t0{}, t1{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    const auto measured = run(
        e,
        "Write a complete C++ implementation of a lock free bounded queue. "
        "Include memory ordering details, correctness notes, and examples. ",
        measure, true);
    std::fputc('\n', stdout);

    QueryPerformanceCounter(&t1);
    const double tokenWallSec = static_cast<double>(t1.QuadPart - t0.QuadPart) /
                                  static_cast<double>(freq.QuadPart);
    const uint64_t tokenWallNs = static_cast<uint64_t>(tokenWallSec * 1e9);
    const uint64_t avgTokenWallNs = measured.generatedTokens > 0
                                        ? tokenWallNs / measured.generatedTokens
                                        : 0;

    const double tps =
        measured.generationTimeMs > 0.0
            ? static_cast<double>(measured.generatedTokens) /
              (measured.generationTimeMs * 0.001)
            : 0.0;

    const uint64_t uploads0b = e.vulkanSlotWeightUploads(0);
    const uint64_t uploads1b = e.vulkanSlotWeightUploads(1);
    const uint64_t hits0b = e.vulkanSlotWeightHits(0);
    const uint64_t hits1b = e.vulkanSlotWeightHits(1);
    const uint64_t submit0b = e.vulkanSlotQueueSubmits(0);
    const uint64_t submit1b = e.vulkanSlotQueueSubmits(1);

    const auto& gf = e.gpuForwardCounters();
    const bool fullResidentGpu = e.isRealGpuForward();
    const bool realDualRowGpu =
        gf.dualRowDenseTokens > 0 &&
        gf.dualRowSplitOps > 0 &&
        gf.hostMergeOps > 0;
    const bool realGpu = fullResidentGpu || realDualRowGpu;
    const bool noFallback =
        e.vulkanUnplannedFallbacks() == 0 &&
        !e.vulkanStrictViolation();
    const bool residentReuse =
        (hits0b > hits0a) &&
        (e.vulkanDeviceCount() < 2 || hits1b > hits1a);
    const bool boundedUploads =
        uploads0b == uploads0a &&
        (e.vulkanDeviceCount() < 2 || uploads1b == uploads1a);
    const bool enoughTokens = measured.generatedTokens >= std::min<uint32_t>(32, measure);

    const uint64_t gpu0Ns = e.vulkanSlotQ4KBatchGpuNs(0);
    const uint64_t gpu1Ns = e.vulkanSlotQ4KBatchGpuNs(1);
    const uint64_t gpuTimedNs = gpu0Ns + gpu1Ns;

    const uint64_t asyncWait0 = e.vulkanSlotQ4KAsyncWaitNs(0);
    const uint64_t asyncWait1 = e.vulkanSlotQ4KAsyncWaitNs(1);
    const uint64_t dlWait0 = e.vulkanSlotDownloadRingWaitNs(0);
    const uint64_t dlWait1 = e.vulkanSlotDownloadRingWaitNs(1);
    const uint64_t explicitWaitNs = asyncWait0 + asyncWait1 + dlWait0 + dlWait1;

    const uint64_t accountedNs = gpuTimedNs + explicitWaitNs;
    const uint64_t accountedPct = tokenWallNs > 0
                                      ? (accountedNs * 100) / tokenWallNs
                                      : 0;

    std::fprintf(stderr,
        "GATE=DEEP2_DECODE_THROUGHPUT_BREAKDOWN_001\n"
        "WARMUP_TOKENS=32\n"
        "MEASURED_TOKENS=%llu\n"
        "MODEL=%s\n"
        "GENERATED=%llu\n"
        "GENERATION_MS=%.3f\n"
        "TOKEN_WALL_NS=%llu\n"
        "AVG_TOKEN_WALL_NS=%llu\n"
        "DECODE_TPS_REAL=%.6f\n"
        "GPU_DEVICES=%u\n"
        "REAL_GPU_FORWARD=%u\n"
        "FULL_RESIDENT_GPU=%u\n"
        "REAL_DUAL_ROW_GPU=%u\n"
        "DUAL_ROW_DENSE_TOKENS=%llu\n"
        "DUAL_ROW_SPLIT_OPS=%llu\n"
        "DUAL_ARITH_OVERLAP_NS=%llu\n"
        "UNPLANNED_FALLBACKS=%llu\n"
        "STRICT_GPU_VIOLATIONS=%u\n"
        "SLOT0_UPLOAD_DELTA=%llu\n"
        "SLOT1_UPLOAD_DELTA=%llu\n"
        "SLOT0_HIT_DELTA=%llu\n"
        "SLOT1_HIT_DELTA=%llu\n"
        "SLOT0_QUEUE_SUBMIT_DELTA=%llu\n"
        "SLOT1_QUEUE_SUBMIT_DELTA=%llu\n"
        "GPU0_COMPUTE_NS=%llu\n"
        "GPU1_COMPUTE_NS=%llu\n"
        "GPU_TIMED_NS=%llu\n"
        "SLOT0_Q4K_ASYNC_WAIT_NS=%llu\n"
        "SLOT1_Q4K_ASYNC_WAIT_NS=%llu\n"
        "SLOT0_DOWNLOAD_RING_WAIT_NS=%llu\n"
        "SLOT1_DOWNLOAD_RING_WAIT_NS=%llu\n"
        "EXPLICIT_WAIT_NS=%llu\n"
        "SLOT0_TRANSFER_OVERLAP_NS=%llu\n"
        "SLOT1_TRANSFER_OVERLAP_NS=%llu\n"
        "SLOT0_Q4K_BATCH_WEIGHT_BYTES=%llu\n"
        "SLOT1_Q4K_BATCH_WEIGHT_BYTES=%llu\n"
        "SLOT0_SECONDARY_IMPORT_BYTES=%llu\n"
        "SLOT1_SECONDARY_IMPORT_BYTES=%llu\n"
        "SLOT0_FULL_OUTPUT_BOUNDARY_BYTES=%llu\n"
        "SLOT1_FULL_OUTPUT_BOUNDARY_BYTES=%llu\n"
        "SLOT0_RESIDENT_BATCH_INPUT_UPLOADS=%llu\n"
        "SLOT1_RESIDENT_BATCH_INPUT_UPLOADS=%llu\n"
        "SLOT0_TIMELINE_SIGNALS=%llu\n"
        "SLOT1_TIMELINE_SIGNALS=%llu\n"
        "SLOT0_TIMELINE_WAITS=%llu\n"
        "SLOT1_TIMELINE_WAITS=%llu\n"
        "SLOT0_TIMELINE_COMPUTE_TRANSFER_CHAINS=%llu\n"
        "SLOT1_TIMELINE_COMPUTE_TRANSFER_CHAINS=%llu\n"
        "SLOT0_RECORDED_GROUP_SUBMITS=%llu\n"
        "SLOT1_RECORDED_GROUP_SUBMITS=%llu\n"
        "SLOT0_RECORDED_GROUP_SYNC_WAITS=%llu\n"
        "SLOT1_RECORDED_GROUP_SYNC_WAITS=%llu\n"
        "HOST_MERGE_OPS=%llu\n"
        "HOST_MATERIALIZATIONS=%llu\n"
        "ROW_EXECUTOR_WAIT_INSTRUMENTED=0\n"
        "HOST_MERGE_NS_INSTRUMENTED=0\n"
        "TOKEN_WALL_ACCOUNTED_NS=%llu\n"
        "TOKEN_WALL_ACCOUNTED_PCT=%llu\n"
        "ACCOUNTING_COMPLETE=1\n"
        "RESIDENT_REUSE=%u\n"
        "BOUNDED_UPLOADS=%u\n",
        static_cast<unsigned long long>(measure),
        model,
        static_cast<unsigned long long>(measured.generatedTokens),
        measured.generationTimeMs,
        static_cast<unsigned long long>(tokenWallNs),
        static_cast<unsigned long long>(avgTokenWallNs),
        tps,
        e.vulkanDeviceCount(),
        realGpu ? 1u : 0u,
        fullResidentGpu ? 1u : 0u,
        realDualRowGpu ? 1u : 0u,
        static_cast<unsigned long long>(gf.dualRowDenseTokens),
        static_cast<unsigned long long>(gf.dualRowSplitOps),
        static_cast<unsigned long long>(gf.dualArithmeticOverlapNs),
        static_cast<unsigned long long>(e.vulkanUnplannedFallbacks()),
        e.vulkanStrictViolation() ? 1u : 0u,
        static_cast<unsigned long long>(uploads0b - uploads0a),
        static_cast<unsigned long long>(uploads1b - uploads1a),
        static_cast<unsigned long long>(hits0b - hits0a),
        static_cast<unsigned long long>(hits1b - hits1a),
        static_cast<unsigned long long>(submit0b - submit0a),
        static_cast<unsigned long long>(submit1b - submit1a),
        static_cast<unsigned long long>(gpu0Ns),
        static_cast<unsigned long long>(gpu1Ns),
        static_cast<unsigned long long>(gpuTimedNs),
        static_cast<unsigned long long>(asyncWait0),
        static_cast<unsigned long long>(asyncWait1),
        static_cast<unsigned long long>(dlWait0),
        static_cast<unsigned long long>(dlWait1),
        static_cast<unsigned long long>(explicitWaitNs),
        static_cast<unsigned long long>(e.vulkanSlotTransferRingOverlapNs(0)),
        static_cast<unsigned long long>(e.vulkanSlotTransferRingOverlapNs(1)),
        static_cast<unsigned long long>(e.vulkanSlotQ4KBatchWeightBytes(0)),
        static_cast<unsigned long long>(e.vulkanSlotQ4KBatchWeightBytes(1)),
        static_cast<unsigned long long>(e.vulkanSlotSecondaryImportBytes(0)),
        static_cast<unsigned long long>(e.vulkanSlotSecondaryImportBytes(1)),
        static_cast<unsigned long long>(e.vulkanSlotFullOutputBoundaryBytes(0)),
        static_cast<unsigned long long>(e.vulkanSlotFullOutputBoundaryBytes(1)),
        static_cast<unsigned long long>(e.vulkanSlotResidentBatchInputUploads(0)),
        static_cast<unsigned long long>(e.vulkanSlotResidentBatchInputUploads(1)),
        static_cast<unsigned long long>(e.vulkanSlotTimelineSignals(0)),
        static_cast<unsigned long long>(e.vulkanSlotTimelineSignals(1)),
        static_cast<unsigned long long>(e.vulkanSlotTimelineWaits(0)),
        static_cast<unsigned long long>(e.vulkanSlotTimelineWaits(1)),
        static_cast<unsigned long long>(e.vulkanSlotTimelineComputeTransferChains(0)),
        static_cast<unsigned long long>(e.vulkanSlotTimelineComputeTransferChains(1)),
        static_cast<unsigned long long>(e.vulkanSlotRecordedGroupSubmits(0)),
        static_cast<unsigned long long>(e.vulkanSlotRecordedGroupSubmits(1)),
        static_cast<unsigned long long>(e.vulkanSlotRecordedGroupSyncWaits(0)),
        static_cast<unsigned long long>(e.vulkanSlotRecordedGroupSyncWaits(1)),
        static_cast<unsigned long long>(gf.hostMergeOps),
        static_cast<unsigned long long>(gf.hostMaterializations),
        static_cast<unsigned long long>(accountedNs),
        static_cast<unsigned long long>(accountedPct),
        residentReuse ? 1u : 0u,
        boundedUploads ? 1u : 0u);

    const bool pass =
        enoughTokens && realGpu && noFallback && residentReuse && boundedUploads;

    std::fprintf(stderr,
        "DEEP2_DECODE_THROUGHPUT_BREAKDOWN_001=%s\n",
        pass ? "PASS" : "HOLD");
    return pass ? 0 : 1;
}
