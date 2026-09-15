#include "deep2/Deep2Engine.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

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
    uint32_t measure = 64;
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

    // Cold pass fills resident packed weights and norm cache.
    const auto warm = run(
        e,
        "Write a detailed C++ implementation of a lock free queue and explain ",
        8, false);
    if (!warm.generatedTokens) {
        std::fprintf(stderr, "QWEN32_40TPS=HOLD stage=warmup\n");
        return 14;
    }

    const uint64_t uploads0a = e.vulkanSlotWeightUploads(0);
    const uint64_t uploads1a = e.vulkanSlotWeightUploads(1);
    const uint64_t hits0a = e.vulkanSlotWeightHits(0);
    const uint64_t hits1a = e.vulkanSlotWeightHits(1);
    const uint64_t submit0a=e.vulkanSlotQueueSubmits(0);
    const uint64_t submit1a=e.vulkanSlotQueueSubmits(1);

    e.reset();
    e.resetGpuForwardCounters();

    const auto measured = run(
        e,
        "Write a complete C++ implementation of a lock free bounded queue. "
        "Include memory ordering details, correctness notes, and examples. ",
        measure, true);
    std::fputc('\n', stdout);

    const double tps =
        measured.generationTimeMs > 0.0
            ? static_cast<double>(measured.generatedTokens) /
              (measured.generationTimeMs * 0.001)
            : 0.0;

    const uint64_t uploads0b = e.vulkanSlotWeightUploads(0);
    const uint64_t uploads1b = e.vulkanSlotWeightUploads(1);
    const uint64_t hits0b = e.vulkanSlotWeightHits(0);
    const uint64_t hits1b = e.vulkanSlotWeightHits(1);
    const uint64_t submit0b=e.vulkanSlotQueueSubmits(0);
    const uint64_t submit1b=e.vulkanSlotQueueSubmits(1);

    const auto& gf=e.gpuForwardCounters();
    const bool fullResidentGpu=e.isRealGpuForward();
    // dualRowSplitOps increments only after both physical GPU row slices
    // completed successfully. Strict mode makes a failed GPU LinearW fatal.
    const bool realDualRowGpu=
        gf.dualRowDenseTokens>0 &&
        gf.dualRowSplitOps>0 &&
        gf.hostMergeOps>0;
    const bool realGpu=fullResidentGpu||realDualRowGpu;
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
    const bool forty = tps >= 40.0;

    std::fprintf(stderr,
        "GATE=DEEP2_QWEN25_32B_REAL_40TPS_001\n"
        "MODEL=%s\n"
        "GENERATED=%llu\n"
        "GENERATION_MS=%.3f\n"
        "DECODE_TPS_REAL=%.6f\n"
        "GPU_DEVICES=%u\n"
        "REAL_GPU_FORWARD=%u\n"
        "FULL_RESIDENT_GPU=%u\n"
        "REAL_DUAL_ROW_GPU=%u\n"
        "DUAL_ROW_DENSE_TOKENS=%llu\n"
        "DUAL_ROW_SPLIT_OPS=%llu\n"
        "DUAL_ARITH_OVERLAP_NS=%llu\n"
        "UNPLANNED_FALLBACKS=%llu\n"
        "STRICT_VIOLATION=%u\n"
        "SLOT0_UPLOAD_DELTA=%llu\n"
        "SLOT1_UPLOAD_DELTA=%llu\n"
        "SLOT0_HIT_DELTA=%llu\n"
        "SLOT1_HIT_DELTA=%llu\n"
        "SLOT0_QUEUE_SUBMIT_DELTA=%llu\n"
        "SLOT1_QUEUE_SUBMIT_DELTA=%llu\n"
        "RESIDENT_REUSE=%u\n"
        "BOUNDED_UPLOADS=%u\n",
        model,
        static_cast<unsigned long long>(measured.generatedTokens),
        measured.generationTimeMs,
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
        static_cast<unsigned long long>(submit0b-submit0a),
        static_cast<unsigned long long>(submit1b-submit1a),
        residentReuse ? 1u : 0u,

        boundedUploads ? 1u : 0u);

    const bool pass =
        enoughTokens && realGpu && noFallback &&
        residentReuse && boundedUploads && forty;

    std::fprintf(stderr,
        "DEEP2_QWEN25_32B_REAL_40TPS_001=%s\n",
        pass ? "PASS" : "HOLD");
    return pass ? 0 : 1;
}
