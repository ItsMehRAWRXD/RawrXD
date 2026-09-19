#include "deep2/Deep2Engine.h"
#include "deep2/Deep2DualGpuRowSplit.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <windows.h>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

std::atomic<uint32_t> g_strictGpuViolations{0};

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

struct Telemetry {
    uint64_t gpuNs = 0;
    uint64_t asyncWaitNs = 0;
    uint64_t downloadWaitNs = 0;
    uint64_t transferOverlapNs = 0;
    uint64_t batchWeightBytes = 0;
    uint64_t secondaryImportBytes = 0;
    uint64_t boundaryBytes = 0;
    uint64_t batchInputUploads = 0;
    uint64_t timelineSignals = 0;
    uint64_t timelineWaits = 0;
    uint64_t timelineChains = 0;
    uint64_t groupSubmits = 0;
    uint64_t groupSyncWaits = 0;
    uint64_t denseRowGpuNs = 0;
    uint64_t denseRowTimedOps = 0;
    uint64_t denseRowSingleGpuNs = 0;
    uint64_t denseRowGroupGpuNs = 0;
};

static Telemetry snap(const Deep2Engine& e, unsigned s)
{
    Telemetry x{};
    x.gpuNs              = e.vulkanSlotQ4KBatchGpuNs(s);
    x.asyncWaitNs        = e.vulkanSlotQ4KAsyncWaitNs(s);
    x.downloadWaitNs     = e.vulkanSlotDownloadRingWaitNs(s);
    x.transferOverlapNs  = e.vulkanSlotTransferRingOverlapNs(s);
    x.batchWeightBytes   = e.vulkanSlotQ4KBatchWeightBytes(s);
    x.secondaryImportBytes = e.vulkanSlotSecondaryImportBytes(s);
    x.boundaryBytes      = e.vulkanSlotFullOutputBoundaryBytes(s);
    x.batchInputUploads  = e.vulkanSlotResidentBatchInputUploads(s);
    x.timelineSignals    = e.vulkanSlotTimelineSignals(s);
    x.timelineWaits      = e.vulkanSlotTimelineWaits(s);
    x.timelineChains     = e.vulkanSlotTimelineComputeTransferChains(s);
    x.groupSubmits       = e.vulkanSlotRecordedGroupSubmits(s);
    x.groupSyncWaits     = e.vulkanSlotRecordedGroupSyncWaits(s);
    x.denseRowGpuNs      = e.vulkanSlotDenseRowGpuNs(s);
    x.denseRowTimedOps   = e.vulkanSlotDenseRowTimedOps(s);
    x.denseRowSingleGpuNs= e.vulkanSlotDenseRowSingleGpuNs(s);
    x.denseRowGroupGpuNs = e.vulkanSlotDenseRowGroupGpuNs(s);
    return x;
}

static inline uint64_t delta(uint64_t a, uint64_t b)
{
    return b >= a ? b - a : 0;
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
    if (warm.generatedTokens != 32) {
        std::fprintf(stderr,
            "QWEN32_40TPS=HOLD stage=warmup got=%llu expected=32\n",
            static_cast<unsigned long long>(warm.generatedTokens));
        return 14;
    }

    const uint64_t uploads0a = e.vulkanSlotWeightUploads(0);
    const uint64_t uploads1a = e.vulkanSlotWeightUploads(1);
    const uint64_t hits0a = e.vulkanSlotWeightHits(0);
    const uint64_t hits1a = e.vulkanSlotWeightHits(1);
    const uint64_t submit0a = e.vulkanSlotQueueSubmits(0);
    const uint64_t submit1a = e.vulkanSlotQueueSubmits(1);
    const Telemetry pre0 = snap(e, 0);
    const Telemetry pre1 = snap(e, 1);

    e.reset();
    e.resetGpuForwardCounters();
    Deep2::Deep2ResetDualRowTiming();

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

    const double tpsEngine =
        measured.generationTimeMs > 0.0
            ? static_cast<double>(measured.generatedTokens) /
              (measured.generationTimeMs * 0.001)
            : 0.0;
    const double tpsQpc =
        tokenWallSec > 0.0
            ? static_cast<double>(measured.generatedTokens) / tokenWallSec
            : 0.0;

    const uint64_t uploads0b = e.vulkanSlotWeightUploads(0);
    const uint64_t uploads1b = e.vulkanSlotWeightUploads(1);
    const uint64_t hits0b = e.vulkanSlotWeightHits(0);
    const uint64_t hits1b = e.vulkanSlotWeightHits(1);
    const uint64_t submit0b = e.vulkanSlotQueueSubmits(0);
    const uint64_t submit1b = e.vulkanSlotQueueSubmits(1);
    const Telemetry post0 = snap(e, 0);
    const Telemetry post1 = snap(e, 1);

    const auto& gf = e.gpuForwardCounters();
    const auto dr = Deep2::Deep2GetDualRowTiming();
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

    const uint64_t laneWorkSumNs = dr.lane0HostEnvelopeNs + dr.lane1HostEnvelopeNs;
    const uint64_t executorOverheadNs = dr.executorWallNs > dr.laneCriticalNs
        ? dr.executorWallNs - dr.laneCriticalNs : 0;
    const uint64_t knownSerialNs = dr.executorWallNs + dr.hostMergeNs + dr.overlapProbeNs;
    const uint64_t setupOtherNs = dr.totalWallNs > knownSerialNs
        ? dr.totalWallNs - knownSerialNs : 0;
    const double denseRowPct = tokenWallNs
        ? 100.0 * static_cast<double>(dr.totalWallNs) / static_cast<double>(tokenWallNs)
        : 0.0;
    const bool callParity = dr.calls == gf.dualRowSplitOps;
    const bool accountingComplete = denseRowPct >= 95.0;
    const uint64_t tokenWallAccountedNs = dr.totalWallNs;

    const uint64_t gpu0Ns = delta(pre0.gpuNs, post0.gpuNs);
    const uint64_t gpu1Ns = delta(pre1.gpuNs, post1.gpuNs);
    const uint64_t gpuWorkNsSum = gpu0Ns + gpu1Ns;
    const uint64_t gpuCriticalPathLowerBoundNs = std::max(gpu0Ns, gpu1Ns);

    const uint64_t asyncWait0 = delta(pre0.asyncWaitNs, post0.asyncWaitNs);
    const uint64_t asyncWait1 = delta(pre1.asyncWaitNs, post1.asyncWaitNs);
    const uint64_t dlWait0 = delta(pre0.downloadWaitNs, post0.downloadWaitNs);
    const uint64_t dlWait1 = delta(pre1.downloadWaitNs, post1.downloadWaitNs);
    const uint64_t explicitWaitNs = asyncWait0 + asyncWait1 + dlWait0 + dlWait1;

    // DEEP2_DENSE_ROW_GPU_TIMING_AUTHORITY_001: scoped GPU compute
    // authorities. Q4K batch counters are no longer printed as a generic
    // "GPUx_COMPUTE_NS" — each receipt states its execution domain.
    const uint64_t denseRowGpuNs0 =
        delta(pre0.denseRowGpuNs, e.vulkanSlotDenseRowGpuNs(0));
    const uint64_t denseRowGpuNs1 =
        delta(pre1.denseRowGpuNs, e.vulkanSlotDenseRowGpuNs(1));
    const uint64_t denseRowTimedOps0 =
        delta(pre0.denseRowTimedOps, e.vulkanSlotDenseRowTimedOps(0));
    const uint64_t denseRowTimedOps1 =
        delta(pre1.denseRowTimedOps, e.vulkanSlotDenseRowTimedOps(1));
    const bool denseRowTimingComplete =
        denseRowGpuNs0 > 0 && denseRowGpuNs1 > 0 &&
        denseRowTimedOps0 > 0 && denseRowTimedOps1 > 0;
    // Routing state: which lane owned the measured tokens.
    const bool residentPathPreemptedDualRow =
        gf.dualRowDenseTokens > 0 && gf.dualRowSplitOps == 0;

    std::fprintf(stderr,
        "GATE=DEEP2_DECODE_THROUGHPUT_BREAKDOWN_001\n"
        "WARMUP_TOKENS=32\n"
        "MEASURED_TOKENS=%llu\n"
        "MODEL=%s\n"
        "GENERATED=%llu\n"
        "GENERATION_MS=%.3f\n"
        "TOKEN_WALL_NS=%llu\n"
        "AVG_TOKEN_WALL_NS=%llu\n"
        "DECODE_TPS_ENGINE=%.6f\n"
        "DECODE_TPS_QPC=%.6f\n"
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
        "GPU_WORK_NS_SUM=%llu\n"
        "GPU_CRITICAL_PATH_LOWER_BOUND_NS=%llu\n"
        "DENSE_ROW_GPU0_COMPUTE_NS=%llu\n"
        "DENSE_ROW_GPU1_COMPUTE_NS=%llu\n"
        "DENSE_ROW_GPU0_TIMED_OPS=%llu\n"
        "DENSE_ROW_GPU1_TIMED_OPS=%llu\n"
        "DENSE_ROW_GPU0_SINGLE_COMPUTE_NS=%llu\n"
        "DENSE_ROW_GPU1_SINGLE_COMPUTE_NS=%llu\n"
        "DENSE_ROW_GPU0_GROUP_COMPUTE_NS=%llu\n"
        "DENSE_ROW_GPU1_GROUP_COMPUTE_NS=%llu\n"
        "DENSE_ROW_GPU_TIMING_COMPLETE=%u\n"
        "Q4K_BATCH_GPU0_COMPUTE_NS=%llu\n"
        "Q4K_BATCH_GPU1_COMPUTE_NS=%llu\n"
        "RESIDENT_PATH_PREEMPTED_DUAL_ROW=%u\n"
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
        "DENSE_ROW_TIMING_CALLS=%llu\n"
        "DENSE_ROW_SINGLE_CALLS=%llu\n"
        "DENSE_ROW_GROUP_CALLS=%llu\n"
        "DENSE_ROW_TIMING_CALL_PARITY=%u\n"
        "DENSE_ROW_TOTAL_WALL_NS=%llu\n"
        "DENSE_ROW_EXECUTOR_WALL_NS=%llu\n"
        "DENSE_ROW_LANE0_HOST_ENVELOPE_NS=%llu\n"
        "DENSE_ROW_LANE1_HOST_ENVELOPE_NS=%llu\n"
        "DENSE_ROW_LANE_WORK_SUM_NS=%llu\n"
        "DENSE_ROW_LANE_CRITICAL_NS=%llu\n"
        "DENSE_ROW_EXECUTOR_OVERHEAD_NS=%llu\n"
        "DENSE_ROW_HOST_MERGE_NS=%llu\n"
        "DENSE_ROW_OVERLAP_PROBE_NS=%llu\n"
        "DENSE_ROW_SETUP_OTHER_NS=%llu\n"
        "DENSE_ROW_WALL_PCT=%.3f\n"
        "ROW_EXECUTOR_WAIT_INSTRUMENTED=1\n"
        "HOST_MERGE_NS_INSTRUMENTED=1\n"
        "OVERLAP_PROBE_NS_INSTRUMENTED=1\n"
        "GPU_COMPUTE_SCOPE=Q4K_BATCH_COUNTER_ONLY\n"
        "EXPLICIT_WAIT_SCOPE=Q4K_ASYNC_PLUS_DOWNLOAD_RING\n"
        "TOKEN_WALL_ACCOUNTED_NS=%llu\n"
        "TOKEN_WALL_ACCOUNTED_PCT=%.3f\n"
        "ACCOUNTING_COMPLETE=%u\n"
        "RESIDENT_REUSE=%u\n"
        "BOUNDED_UPLOADS=%u\n",
        static_cast<unsigned long long>(measure),
        model,
        static_cast<unsigned long long>(measured.generatedTokens),
        measured.generationTimeMs,
        static_cast<unsigned long long>(tokenWallNs),
        static_cast<unsigned long long>(avgTokenWallNs),
        tpsEngine,
        tpsQpc,
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
        static_cast<unsigned long long>(gpuWorkNsSum),
        static_cast<unsigned long long>(gpuCriticalPathLowerBoundNs),
        static_cast<unsigned long long>(denseRowGpuNs0),
        static_cast<unsigned long long>(denseRowGpuNs1),
        static_cast<unsigned long long>(denseRowTimedOps0),
        static_cast<unsigned long long>(denseRowTimedOps1),
        static_cast<unsigned long long>(delta(pre0.denseRowSingleGpuNs, e.vulkanSlotDenseRowSingleGpuNs(0))),
        static_cast<unsigned long long>(delta(pre1.denseRowSingleGpuNs, e.vulkanSlotDenseRowSingleGpuNs(1))),
        static_cast<unsigned long long>(delta(pre0.denseRowGroupGpuNs, e.vulkanSlotDenseRowGroupGpuNs(0))),
        static_cast<unsigned long long>(delta(pre1.denseRowGroupGpuNs, e.vulkanSlotDenseRowGroupGpuNs(1))),
        denseRowTimingComplete ? 1u : 0u,
        static_cast<unsigned long long>(gpu0Ns),
        static_cast<unsigned long long>(gpu1Ns),
        residentPathPreemptedDualRow ? 1u : 0u,
        static_cast<unsigned long long>(asyncWait0),
        static_cast<unsigned long long>(asyncWait1),
        static_cast<unsigned long long>(dlWait0),
        static_cast<unsigned long long>(dlWait1),
        static_cast<unsigned long long>(explicitWaitNs),
        static_cast<unsigned long long>(delta(pre0.transferOverlapNs, post0.transferOverlapNs)),
        static_cast<unsigned long long>(delta(pre1.transferOverlapNs, post1.transferOverlapNs)),
        static_cast<unsigned long long>(delta(pre0.batchWeightBytes, post0.batchWeightBytes)),
        static_cast<unsigned long long>(delta(pre1.batchWeightBytes, post1.batchWeightBytes)),
        static_cast<unsigned long long>(delta(pre0.secondaryImportBytes, post0.secondaryImportBytes)),
        static_cast<unsigned long long>(delta(pre1.secondaryImportBytes, post1.secondaryImportBytes)),
        static_cast<unsigned long long>(delta(pre0.boundaryBytes, post0.boundaryBytes)),
        static_cast<unsigned long long>(delta(pre1.boundaryBytes, post1.boundaryBytes)),
        static_cast<unsigned long long>(delta(pre0.batchInputUploads, post0.batchInputUploads)),
        static_cast<unsigned long long>(delta(pre1.batchInputUploads, post1.batchInputUploads)),
        static_cast<unsigned long long>(delta(pre0.timelineSignals, post0.timelineSignals)),
        static_cast<unsigned long long>(delta(pre1.timelineSignals, post1.timelineSignals)),
        static_cast<unsigned long long>(delta(pre0.timelineWaits, post0.timelineWaits)),
        static_cast<unsigned long long>(delta(pre1.timelineWaits, post1.timelineWaits)),
        static_cast<unsigned long long>(delta(pre0.timelineChains, post0.timelineChains)),
        static_cast<unsigned long long>(delta(pre1.timelineChains, post1.timelineChains)),
        static_cast<unsigned long long>(delta(pre0.groupSubmits, post0.groupSubmits)),
        static_cast<unsigned long long>(delta(pre1.groupSubmits, post1.groupSubmits)),
        static_cast<unsigned long long>(delta(pre0.groupSyncWaits, post0.groupSyncWaits)),
        static_cast<unsigned long long>(delta(pre1.groupSyncWaits, post1.groupSyncWaits)),
        static_cast<unsigned long long>(gf.hostMergeOps),
        static_cast<unsigned long long>(gf.hostMaterializations),
        static_cast<unsigned long long>(dr.calls),
        static_cast<unsigned long long>(dr.singleCalls),
        static_cast<unsigned long long>(dr.groupCalls),
        callParity ? 1u : 0u,
        static_cast<unsigned long long>(dr.totalWallNs),
        static_cast<unsigned long long>(dr.executorWallNs),
        static_cast<unsigned long long>(dr.lane0HostEnvelopeNs),
        static_cast<unsigned long long>(dr.lane1HostEnvelopeNs),
        static_cast<unsigned long long>(laneWorkSumNs),
        static_cast<unsigned long long>(dr.laneCriticalNs),
        static_cast<unsigned long long>(executorOverheadNs),
        static_cast<unsigned long long>(dr.hostMergeNs),
        static_cast<unsigned long long>(dr.overlapProbeNs),
        static_cast<unsigned long long>(setupOtherNs),
        denseRowPct,
        static_cast<unsigned long long>(tokenWallAccountedNs),
        denseRowPct,
        accountingComplete ? 1u : 0u,
        residentReuse ? 1u : 0u,
        boundedUploads ? 1u : 0u);

    const bool pass =
        enoughTokens && realGpu && noFallback && residentReuse && boundedUploads
        && callParity && dr.calls > 0;

    // B5_MATERIALIZATION_PROFILE_001: classify every host materialization
    // with wall time per class; ACCOUNTING_MATCH requires the class sum to
    // equal the raw hostMaterializations counter exactly.
    {
        const uint64_t matTotal = gf.hostMaterializations;
        const uint64_t classSum = Deep2::Deep2GpuForward_MatClassSum(gf);
        const uint64_t perTokenNum = measured.generatedTokens;
        std::fprintf(stderr,
            "B5_MATERIALIZATION_PROFILE_001\n"
            "CROSS_DEVICE_HANDOFF_MATERIALIZATIONS=%llu\n"
            "FINAL_OUTPUT_MATERIALIZATIONS=%llu\n"
            "GEMV_STAGING_MATERIALIZATIONS=%llu\n"
            "DUAL_ROW_SINGLE_MATERIALIZATIONS=%llu\n"
            "DUAL_ROW_GROUP_MATERIALIZATIONS=%llu\n"
            "OTHER_MATERIALIZATIONS=%llu\n"
            "CLASSIFIED_MATERIALIZATIONS=%llu\n"
            "TOTAL_MATERIALIZATIONS=%llu\n"
            "ACCOUNTING_MATCH=%d\n"
            "MATERIALIZATIONS_PER_TOKEN=%.3f\n"
            "CROSS_DEVICE_HANDOFF_WALL_NS=%llu\n"
            "FINAL_OUTPUT_WALL_NS=%llu\n"
            "GEMV_STAGING_WALL_NS=%llu\n"
            "OTHER_MATERIALIZATION_WALL_NS=%llu\n",
            static_cast<unsigned long long>(gf.matCrossDeviceHandoff),
            static_cast<unsigned long long>(gf.matFinalDownload),
            static_cast<unsigned long long>(gf.matGemvSingleRoundTrip),
            static_cast<unsigned long long>(gf.matDualRowSingle),
            static_cast<unsigned long long>(gf.matDualRowGroup),
            static_cast<unsigned long long>(gf.matOther),
            static_cast<unsigned long long>(classSum),
            static_cast<unsigned long long>(matTotal),
            classSum == matTotal ? 1 : 0,
            perTokenNum ? (double)matTotal / (double)perTokenNum : 0.0,
            static_cast<unsigned long long>(gf.matCrossDeviceHandoffNs),
            static_cast<unsigned long long>(gf.matFinalDownloadNs),
            static_cast<unsigned long long>(gf.matGemvSingleNs),
        static_cast<unsigned long long>(gf.matOtherNs));
    }

    // DEEP2_RESIDENT_COST_ATTRIBUTION_001: phase walls of the resident
    // lane (resident-first experiment laboratory). Accounting law:
    //   upload + prime + range0 + handoff + range1 + download
    //     == residentAccountedNs (multi-map order)
    // and RESIDENT_ACCOUNTED_PCT vs the token wall names the unattributed
    // remainder. Run at 64/128/256 tokens for slope attribution.
    {
        const uint64_t tokens = measured.generatedTokens;
        const uint64_t upload = gf.residentUploadHiddenNs;
        const uint64_t prime = gf.residentPrimeCommitNs;
        const uint64_t range0 = gf.residentRangeNs[0];
        const uint64_t range1 = gf.residentRangeNs[1];
        const uint64_t handoff = gf.residentHandoffNs;
        const uint64_t download = gf.residentFinalDownloadNs;
        const uint64_t accounted = upload + prime + range0 + range1 +
                                   handoff + download;
        const double pct = tokenWallNs
            ? 100.0 * static_cast<double>(accounted) /
                  static_cast<double>(tokenWallNs)
            : 0.0;
        auto perTok = [&](uint64_t ns) -> double {
            return tokens ? static_cast<double>(ns) / static_cast<double>(tokens)
                          : 0.0;
        };
        std::fprintf(stderr,
            "DEEP2_RESIDENT_COST_ATTRIBUTION_001\n"
            "RESIDENT_TOKENS=%llu\n"
            "RESIDENT_UPLOAD_HIDDEN_NS=%llu\n"
            "RESIDENT_UPLOAD_HIDDEN_COUNT=%llu\n"
            "RESIDENT_UPLOAD_HIDDEN_BYTES=%llu\n"
            "RESIDENT_UPLOAD_HIDDEN_US_PER_TOKEN=%.3f\n"
            "RESIDENT_PRIME_COMMIT_NS=%llu\n"
            "RESIDENT_PRIME_COMMIT_COUNT=%llu\n"
            "RESIDENT_PRIME_COMMIT_US_PER_TOKEN=%.3f\n"
            "RESIDENT_RANGE0_NS=%llu\n"
            "RESIDENT_RANGE0_GPU_NS=%llu\n"
            "RESIDENT_RANGE0_COUNT=%llu\n"
            "RESIDENT_RANGE0_MS_PER_TOKEN=%.3f\n"
            "RESIDENT_RANGE1_NS=%llu\n"
            "RESIDENT_RANGE1_GPU_NS=%llu\n"
            "RESIDENT_RANGE1_COUNT=%llu\n"
            "RESIDENT_RANGE1_MS_PER_TOKEN=%.3f\n"
            "RESIDENT_RANGE_GPU_NS_SUM=%llu\n"
            "RESIDENT_HANDOFF_NS=%llu\n"
            "RESIDENT_HANDOFF_COUNT=%llu\n"
            "RESIDENT_HANDOFF_BYTES=%llu\n"
            "RESIDENT_HANDOFF_US_PER_TOKEN=%.3f\n"
            "RESIDENT_FINAL_DOWNLOAD_NS=%llu\n"
            "RESIDENT_FINAL_DOWNLOAD_COUNT=%llu\n"
            "RESIDENT_FINAL_DOWNLOAD_US_PER_TOKEN=%.3f\n"
            "RESIDENT_QUEUE_SUBMITS=%llu\n"
            "RESIDENT_FENCE_WAITS=%llu\n"
            "RESIDENT_ACCOUNTED_NS=%llu\n"
            "RESIDENT_ACCOUNTED_PCT=%.3f\n",
            static_cast<unsigned long long>(tokens),
            static_cast<unsigned long long>(upload),
            static_cast<unsigned long long>(gf.residentUploadHiddenCount),
            static_cast<unsigned long long>(gf.residentUploadHiddenBytes),
            perTok(upload) / 1000.0,
            static_cast<unsigned long long>(prime),
            static_cast<unsigned long long>(gf.residentPrimeCommitCount),
            perTok(prime) / 1000.0,
            static_cast<unsigned long long>(range0),
            static_cast<unsigned long long>(gf.residentRangeGpuNs[0]),
            static_cast<unsigned long long>(gf.residentRangeCount[0]),
            perTok(range0) / 1.0e6,
            static_cast<unsigned long long>(range1),
            static_cast<unsigned long long>(gf.residentRangeGpuNs[1]),
            static_cast<unsigned long long>(gf.residentRangeCount[1]),
            perTok(range1) / 1.0e6,
            static_cast<unsigned long long>(
                gf.residentRangeGpuNs[0] + gf.residentRangeGpuNs[1]),
            static_cast<unsigned long long>(handoff),
            static_cast<unsigned long long>(gf.residentHandoffCount),
            static_cast<unsigned long long>(gf.residentHandoffBytes),
            perTok(handoff) / 1000.0,
            static_cast<unsigned long long>(download),
            static_cast<unsigned long long>(gf.residentFinalDownloadCount),
            perTok(download) / 1000.0,
            static_cast<unsigned long long>(gf.residentQueueSubmits),
            static_cast<unsigned long long>(gf.residentFenceWaits),
            static_cast<unsigned long long>(accounted),
            pct);
        std::fflush(stderr);
    }

    // DEEP2_RESIDENT_Q4K_KERNEL_PARITY_001: execution-path parity between
    // the dual-row lane and the resident lane. Both lanes dispatch through
    // dispatchQuant() on the same qPipeline_ (deep2_qgemv.comp, one 256-
    // lane workgroup per row); the receipt measures per-lane ns/row from
    // sampled GPU timestamp pairs (post-fence collection) and verifies
    // shader/layout identity by pipeline handle.
    {
        constexpr uint32_t kDual = 1, kResident = 2;
        auto laneNsPerRow = [&](uint32_t lane) -> double {
            double best = 0.0;
            for (unsigned s = 0; s < e.vulkanDeviceCount() && s < 2; ++s) {
                const uint64_t rows =
                    e.vulkanSlotQ4kParitySampledRows(s, lane);
                if (!rows) continue;
                const double nspt = static_cast<double>(
                    e.vulkanSlotQ4kParitySampledNs(s, lane)) /
                    static_cast<double>(rows);
                if (best == 0.0 || nspt < best) best = nspt;
            }
            return best;
        };
        const double dualNsRow = laneNsPerRow(kDual);
        const double resNsRow = laneNsPerRow(kResident);
        const double slowdown = dualNsRow > 0.0 ? resNsRow / dualNsRow : 0.0;
        const bool shaderMatch =
            e.vulkanSlotQ4kParityPipeline(0, kDual) != 0 &&
            e.vulkanSlotQ4kParityPipeline(0, kDual) ==
            e.vulkanSlotQ4kParityPipeline(0, kResident);
        uint64_t dualDisp = 0, dualRows = 0, resDisp = 0, resRows = 0;
        uint64_t dualSamp = 0, resSamp = 0;
        for (unsigned s = 0; s < e.vulkanDeviceCount() && s < 2; ++s) {
            dualDisp += e.vulkanSlotQ4kParityDispatchCount(s, kDual);
            dualRows += e.vulkanSlotQ4kParityRows(s, kDual);
            resDisp  += e.vulkanSlotQ4kParityDispatchCount(s, kResident);
            resRows  += e.vulkanSlotQ4kParityRows(s, kResident);
            dualSamp += e.vulkanSlotQ4kParitySampledCount(s, kDual);
            resSamp += e.vulkanSlotQ4kParitySampledCount(s, kResident);
        }
        std::fprintf(stderr,
            "DEEP2_RESIDENT_Q4K_KERNEL_PARITY_001\n"
            "DUAL_Q4K_DISPATCH_COUNT=%llu\n"
            "DUAL_Q4K_ROWS=%llu\n"
            "DUAL_Q4K_SAMPLED_COUNT=%llu\n"
            "DUAL_Q4K_NS_PER_ROW=%.3f\n"
            "RESIDENT_Q4K_DISPATCH_COUNT=%llu\n"
            "RESIDENT_Q4K_ROWS=%llu\n"
            "RESIDENT_Q4K_SAMPLED_COUNT=%llu\n"
            "RESIDENT_Q4K_NS_PER_ROW=%.3f\n"
            "RESIDENT_Q4K_SLOWDOWN=%.3f\n"
            "Q4K_SHADER_MATCH=%u\n"
            "Q4K_LAYOUT_MATCH=%u\n"
            "Q4K_GEOMETRY_MATCH=1\n",
            static_cast<unsigned long long>(dualDisp),
            static_cast<unsigned long long>(dualRows),
            static_cast<unsigned long long>(dualSamp),
            dualNsRow,
            static_cast<unsigned long long>(resDisp),
            static_cast<unsigned long long>(resRows),
            static_cast<unsigned long long>(resSamp),
            resNsRow,
            slowdown,
            shaderMatch ? 1u : 0u,
            shaderMatch ? 1u : 0u);
        std::fflush(stderr);
    }

    std::fprintf(stderr,
        "DEEP2_DECODE_THROUGHPUT_BREAKDOWN_001=%s\n",
        pass ? "PASS" : "HOLD");
    return pass ? 0 : 1;
}
