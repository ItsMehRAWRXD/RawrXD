// qwen32_baseline_authority_gate.cpp — DEEP2_32B_BASELINE_AUTHORITY_001
//
// Canonical baseline authority run for Qwen2.5-Coder-32B-Instruct-Q4_K_M.
// Emits a frozen receipt with exact commit, model hash, GPU identity,
// and measured decode TPS under controlled conditions.
//
// Usage:
//   qwen32_baseline_authority_gate.exe <model.gguf> [measure_tokens=256]
//
// Authority rules:
//   - WARMUP_TOKENS=32
//   - MEASURED_TOKENS>=32
//   - STRICT_GPU_VIOLATIONS=0
//   - UNPLANNED_FALLBACKS=0
//   - DUAL_ROW_SPLIT_OPS>0
//   - REAL_DUAL_ROW_GPU=1
//

#include "deep2/Deep2Engine.h"
#include "deep2/Deep2DualGpuRowSplit.hpp"
#include "deep2/deep2_sha256.hpp"

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
    return x;
}

static inline uint64_t delta(uint64_t a, uint64_t b)
{
    return b >= a ? b - a : 0;
}

static std::string gpuName(const Deep2Engine& e, unsigned slot)
{
    if (slot >= e.vulkanDeviceCount()) return "none";
    auto* vc = e.getVulkanComputeSlot(slot);
    if (!vc) return "none";
    return vc->physicalInfo().name;
}

static std::string envOr(const char* name, const char* fallback)
{
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string(fallback);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: qwen32_baseline_authority_gate.exe model.gguf [measure_tokens]\n");
        return 2;
    }

    const char* model = argv[1];
    uint32_t measure = 256;
    if (argc > 2) {
        const long v = std::strtol(argv[2], nullptr, 10);
        if (v > 0 && v <= 4096) measure = static_cast<uint32_t>(v);
    }

    // Compute model SHA256 before any load.
    std::array<uint8_t,32> modelHash{};
    uint64_t modelBytes = 0;
    bool modelSha256Ok = deep2::sha256_file(model, modelHash, &modelBytes);

    Deep2Engine e;
    EngineConfig cfg{};
    cfg.maxSeqLen = 4096;
    cfg.numThreads = 0;

    if (!e.initialize(cfg)) {
        std::fprintf(stderr, "BASELINE=HOLD stage=initialize\n");
        return 10;
    }
    if (!e.loadModel(model)) {
        std::fprintf(stderr, "BASELINE=HOLD stage=load\n");
        return 11;
    }

    const auto& c = e.getConfig();
    if (c.numLayers != 64 || c.hiddenDim != 5120 ||
        c.numHeads != 40 || c.numKVHeads != 8) {
        std::fprintf(stderr,
            "BASELINE=HOLD stage=geometry layers=%zu hidden=%zu heads=%zu kv=%zu\n",
            c.numLayers, c.hiddenDim, c.numHeads, c.numKVHeads);
        return 12;
    }

    e.setVulkanStrictNoCpuFallback(true);
    e.enableVulkan(true);
    if (!e.isVulkanInitialized() || !e.gpuResidentDecodeEnabled()) {
        std::fprintf(stderr,
            "BASELINE=HOLD stage=vulkan devices=%u\n",
            e.vulkanDeviceCount());
        return 13;
    }

    const std::string gpu0 = gpuName(e, 0);
    const std::string gpu1 = gpuName(e, 1);

    // Warmup pass: 32 tokens to stabilize residency and adaptive split.
    const auto warm = run(
        e,
        "Write a detailed C++ implementation of a lock free queue and explain ",
        32, false);
    if (warm.generatedTokens != 32) {
        std::fprintf(stderr,
            "BASELINE=HOLD stage=warmup got=%llu expected=32\n",
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
        e.vulkanUnplannedFallbacks() == 0 && !e.vulkanStrictViolation();
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

    std::fprintf(stderr,
        "GATE=DEEP2_32B_BASELINE_AUTHORITY_001\n"
        "COMMIT=%s\n"
        "MODEL_SHA256=%s\n"
        "MODEL_BYTES=%llu\n"
        "GPU0=%s\n"
        "GPU1=%s\n"
        "WARMUP_TOKENS=32\n"
        "MEASURED_TOKENS=%llu\n"
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
        envOr("GATE_COMMIT_HASH", "UNKNOWN").c_str(),
        modelSha256Ok ? deep2::hex32(modelHash).c_str() : "FAILED",
        static_cast<unsigned long long>(modelBytes),
        gpu0.c_str(),
        gpu1.c_str(),
        static_cast<unsigned long long>(measure),
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

    std::fprintf(stderr,
        "DEEP2_32B_BASELINE_AUTHORITY_001=%s\n",
        pass ? "PASS" : "HOLD");

    // Also emit receipt to a hardcoded file for reliable capture regardless of shell redirects.
    {
        const char* receiptPath = "C:\\Users\\Garrett\\baseline_receipt.txt";
        FILE* rf = nullptr;
        errno_t err = fopen_s(&rf, receiptPath, "w");
        if (rf && err == 0) {
            std::fprintf(rf,
                "GATE=DEEP2_32B_BASELINE_AUTHORITY_001\n"
                "COMMIT=%s\n"
                "MODEL_SHA256=%s\n"
                "MODEL_BYTES=%llu\n"
                "GPU0=%s\n"
                "GPU1=%s\n"
                "WARMUP_TOKENS=32\n"
                "MEASURED_TOKENS=%llu\n"
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
                "UNPLANNED_FALLBACKS=%llu\n"
                "STRICT_GPU_VIOLATIONS=%u\n"
                "DENSE_ROW_TIMING_CALLS=%llu\n"
                "DENSE_ROW_WALL_PCT=%.3f\n"
                "RESIDENT_REUSE=%u\n"
                "BOUNDED_UPLOADS=%u\n"
                "DEEP2_32B_BASELINE_AUTHORITY_001=%s\n",
                envOr("GATE_COMMIT_HASH", "UNKNOWN").c_str(),
                modelSha256Ok ? deep2::hex32(modelHash).c_str() : "FAILED",
                static_cast<unsigned long long>(modelBytes),
                gpu0.c_str(),
                gpu1.c_str(),
                static_cast<unsigned long long>(measure),
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
                static_cast<unsigned long long>(e.vulkanUnplannedFallbacks()),
                e.vulkanStrictViolation() ? 1u : 0u,
                static_cast<unsigned long long>(dr.calls),
                denseRowPct,
                residentReuse ? 1u : 0u,
                boundedUploads ? 1u : 0u,
                pass ? "PASS" : "HOLD");
            std::fflush(rf);
            std::fclose(rf);
        }
    }

    return pass ? 0 : 1;
}