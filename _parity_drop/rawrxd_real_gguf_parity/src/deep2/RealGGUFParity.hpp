#pragma once
// ============================================================================
// RAWRXD_REAL_GGUF_PARITY_001
// Real-GGUF CPU-reference <-> strict-Vulkan token/logit parity authority.
// C++20 only. No third-party dependencies.
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2::Parity {

struct Thresholds {
    double absMax      = 5e-3;   // maximum absolute logit delta
    double relMax      = 5e-3;   // maximum normalized relative delta
    double rmsMax      = 1e-3;   // RMS logit delta
    double cosineMin   = 0.99999;
    std::size_t topK   = 10;
    bool requireTop1Exact = true;
    bool requireTopKSetExact = false;
    bool requireRealGpu = true;
    bool requireZeroFallback = true;
};

struct Config {
    std::string modelPath;
    std::string prompt = "The meaning of life is";
    std::string receiptPath = "real_gguf_parity_receipt.txt";
    std::string cpuTracePath = "real_gguf_parity_cpu.trace";
    std::string gpuTracePath = "real_gguf_parity_gpu.trace";
    std::string goldenPath;
    std::size_t decodeSteps = 8;
    std::size_t maxSeqLen = 4096;
    std::size_t numThreads = 0;
    Thresholds thresholds{};
    bool writeGolden = false;
    bool verifyGoldenOnly = false;
    bool enableCheckpointTrace = true;
};

struct StepMetrics {
    std::size_t step = 0;
    int32_t teacherToken = -1;
    int32_t cpuTop1 = -1;
    int32_t gpuTop1 = -1;
    double maxAbs = 0.0;
    double meanAbs = 0.0;
    double rms = 0.0;
    double maxRel = 0.0;
    double cosine = 0.0;
    std::size_t topKIntersection = 0;
    bool finite = false;
    bool pass = false;
};

struct Result {
    bool pass = false;
    std::string failStage;
    std::string message;

    std::string modelSha256;
    std::uint64_t modelBytes = 0;
    std::string architecture;

    std::vector<int32_t> promptTokens;
    std::vector<int32_t> teacherTokens;
    std::vector<StepMetrics> steps;

    bool cpuReferenceOk = false;
    bool gpuReplayOk = false;
    bool tokenParity = false;
    bool logitParity = false;
    bool checkpointTraceCompared = false;
    bool checkpointTracePass = false;

    bool realGpuForward = false;
    std::uint64_t gpuGemvSuccess = 0;
    std::uint64_t gpuFallbackDelta = 0;
    bool gpuStrictViolation = false;

    std::size_t traceLinesCompared = 0;
    std::size_t traceLinesMissing = 0;
    std::size_t traceMetricFailures = 0;
};

Result RunRealGgufParity(const Config& cfg);
int RunRealGgufParityCli(int argc, char** argv);

} // namespace Deep2::Parity
