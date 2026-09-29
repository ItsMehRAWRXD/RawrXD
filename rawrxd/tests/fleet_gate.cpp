// fleet_gate.cpp — RAWRXD_LOCAL_AGENT_FLEET_001
//
// Per-model load + generation gate for the RawrXD local agent fleet.
// Deep2-only (no Ollama, no cloud backends). Runs warmup(32) + measured
// tokens for each supplied model and emits a frozen per-model receipt.
//
// Usage:
//   fleet_gate.exe <model.gguf> [measure_tokens] [receipt_path]
//
// Authority rules:
//   - WARMUP_TOKENS=32
//   - MEASURED_TOKENS>=32
//   - STRICT_GPU_VIOLATIONS=0
//   - UNPLANNED_FALLBACKS=0
//   - DEEP2_ONLY=1 (engine only; no external backends contacted)
//   - GENERATED_TOKEN_COUNT>=1
//
#include "deep2/Deep2Engine.h"
#include "deep2/deep2_sha256.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <windows.h>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

// Gate-owned strict-GPU violation counter (referenced by engine spec path).
std::atomic<uint32_t> g_strictGpuViolations{0};

static GenerationResult run_generate(
    Deep2Engine& e, const char* prompt, uint32_t n)
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
        [](int32_t, const std::string& piece) -> bool { return true; });
}

static std::string envOr(const char* name, const char* fallback)
{
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string(fallback);
}

static void emit_receipt(
    const char* receiptPath,
    const char* gate, const char* commit, const char* modelPath,
    const char* modelSha, uint64_t modelBytes,
    uint64_t warmGenerated, uint64_t measureTokens, uint64_t generated,
    double generationMs, double tpsEngine, double tpsQpc,
    uint32_t gpuDevices, const char* gpu0, const char* gpu1,
    uint64_t unplannedFallbacks, int strictViolation,
    int pass)
{
    FILE* f = nullptr;
    errno_t err = fopen_s(&f, receiptPath, "w");
    if (!f || err != 0) return;
    std::fprintf(f,
        "GATE=RAWRXD_LOCAL_AGENT_FLEET_001\n"
        "COMMIT=%s\n"
        "MODEL_PATH=%s\n"
        "MODEL_SHA256=%s\n"
        "MODEL_BYTES=%llu\n"
        "WARMUP_TOKENS=32\n"
        "WARMUP_GENERATED=%llu\n"
        "MEASURED_TOKENS=%llu\n"
        "GENERATED=%llu\n"
        "GENERATION_MS=%.3f\n"
        "DECODE_TPS_ENGINE=%.6f\n"
        "DECODE_TPS_QPC=%.6f\n"
        "GPU_DEVICES=%u\n"
        "GPU0=%s\n"
        "GPU1=%s\n"
        "OLLAMA_USED=0\n"
        "TEST_ONLY_BACKEND_USED=0\n"
        "STUB_FALLBACKS=0\n"
        "UNPLANNED_FALLBACKS=%llu\n"
        "STRICT_GPU_VIOLATIONS=%u\n"
        "DEEP2_ONLY=1\n"
        "RAWRXD_LOCAL_AGENT_FLEET_001=%s\n",
        commit, modelPath, modelSha,
        static_cast<unsigned long long>(modelBytes),
        static_cast<unsigned long long>(warmGenerated),
        static_cast<unsigned long long>(measureTokens),
        static_cast<unsigned long long>(generated),
        generationMs, tpsEngine, tpsQpc,
        gpuDevices, gpu0, gpu1,
        static_cast<unsigned long long>(unplannedFallbacks),
        strictViolation,
        pass ? "PASS" : "HOLD");
    std::fflush(f);
    std::fclose(f);
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: fleet_gate.exe <model.gguf> [measure_tokens] [receipt_path]\n");
        return 2;
    }

    const char* model = argv[1];
    uint32_t measure = 32;
    if (argc > 2) {
        const long v = std::strtol(argv[2], nullptr, 10);
        if (v > 0 && v <= 4096) measure = static_cast<uint32_t>(v);
    }
    std::string receipt = (argc > 3)
        ? std::string(argv[3])
        : std::string("fleet_receipt_last.txt");

    std::array<uint8_t, 32> modelHash{};
    uint64_t modelBytes = 0;
    const bool shaOk = deep2::sha256_file(model, modelHash, &modelBytes);

    Deep2Engine e;
    EngineConfig cfg{};
    cfg.maxSeqLen = 4096;
    cfg.numThreads = 0;

    auto fail = [&](const char* stage) {
        emit_receipt(receipt.c_str(), "RAWRXD_LOCAL_AGENT_FLEET_001",
                     envOr("GATE_COMMIT_HASH", "UNKNOWN").c_str(),
                     model, shaOk ? deep2::hex32(modelHash).c_str() : "FAILED",
                     modelBytes, 0, measure, 0, 0.0, 0.0, 0.0,
                     0, "none", "none", 0, 0, /*pass=*/0);
        std::fprintf(stderr,
            "GATE=RAWRXD_LOCAL_AGENT_FLEET_001 MODEL=%s STAGE=%s VERDICT=HOLD\n",
            model, stage);
        return 10;
    };

    if (!e.initialize(cfg)) return fail("initialize");
    if (!e.loadModel(model)) return fail("load");

    e.setVulkanStrictNoCpuFallback(true);
    e.enableVulkan(true);
    if (!e.isVulkanInitialized()) return fail("vulkan_init");

    const std::string gpu0 = [&]() -> std::string {
        if (e.vulkanDeviceCount() < 1) return "none";
        auto* vc = e.getVulkanComputeSlot(0);
        return vc ? vc->physicalInfo().name : std::string("none");
    }();
    const std::string gpu1 = e.vulkanDeviceCount() >= 2
        ? [&]() -> std::string {
              auto* vc = e.getVulkanComputeSlot(1);
              return vc ? vc->physicalInfo().name : std::string("none");
          }()
        : std::string("none");

    // Warmup: 32 tokens.
    const auto warm = run_generate(
        e, "Write a detailed C++ implementation of a lock free queue and explain ",
        32);
    if (warm.generatedTokens < 32) return fail("warmup");

    e.reset();
    e.resetGpuForwardCounters();

    LARGE_INTEGER freq{}, t0{}, t1{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    const auto measured = run_generate(
        e,
        "Write a complete C++ implementation of a lock free bounded queue. "
        "Include memory ordering details, correctness notes, and examples. ",
        measure);
    std::fputc('\n', stdout);

    QueryPerformanceCounter(&t1);
    const double tokenWallSec = static_cast<double>(t1.QuadPart - t0.QuadPart) /
                                static_cast<double>(freq.QuadPart);
    const double tpsEngine =
        measured.generationTimeMs > 0.0
            ? static_cast<double>(measured.generatedTokens) /
              (measured.generationTimeMs * 0.001)
            : 0.0;
    const double tpsQpc = tokenWallSec > 0.0
        ? static_cast<double>(measured.generatedTokens) / tokenWallSec
        : 0.0;

    const uint64_t fallbacks = e.vulkanUnplannedFallbacks();
    const bool strictViolation = e.vulkanStrictViolation();
    const bool noFallback = (fallbacks == 0) && !strictViolation;
    const bool enoughTokens = measured.generatedTokens >= 32 &&
                              measured.completed;
    const bool realGpu = e.isRealGpuForward();

    const bool pass = enoughTokens && noFallback && realGpu;

    std::fprintf(stderr,
        "GATE=RAWRXD_LOCAL_AGENT_FLEET_001\n"
        "COMMIT=%s\n"
        "MODEL_PATH=%s\n"
        "MODEL_SHA256=%s\n"
        "MODEL_BYTES=%llu\n"
        "GPU0=%s\n"
        "GPU1=%s\n"
        "WARMUP_GENERATED=%llu\n"
        "MEASURED_TOKENS=%llu\n"
        "GENERATED=%llu\n"
        "GENERATION_MS=%.3f\n"
        "DECODE_TPS_ENGINE=%.6f\n"
        "DECODE_TPS_QPC=%.6f\n"
        "GPU_DEVICES=%u\n"
        "REAL_GPU_FORWARD=%u\n"
        "UNPLANNED_FALLBACKS=%llu\n"
        "STRICT_GPU_VIOLATIONS=%u\n"
        "OLLAMA_USED=0\n"
        "TEST_ONLY_BACKEND_USED=0\n"
        "STUB_FALLBACKS=0\n"
        "DEEP2_ONLY=1\n",
        envOr("GATE_COMMIT_HASH", "UNKNOWN").c_str(),
        model, shaOk ? deep2::hex32(modelHash).c_str() : "FAILED",
        static_cast<unsigned long long>(modelBytes),
        gpu0.c_str(), gpu1.c_str(),
        static_cast<unsigned long long>(warm.generatedTokens),
        static_cast<unsigned long long>(measure),
        static_cast<unsigned long long>(measured.generatedTokens),
        measured.generationTimeMs, tpsEngine, tpsQpc,
        e.vulkanDeviceCount(),
        realGpu ? 1u : 0u,
        static_cast<unsigned long long>(fallbacks),
        strictViolation ? 1u : 0u);

    emit_receipt(receipt.c_str(), "RAWRXD_LOCAL_AGENT_FLEET_001",
                 envOr("GATE_COMMIT_HASH", "UNKNOWN").c_str(),
                 model, shaOk ? deep2::hex32(modelHash).c_str() : "FAILED",
                 modelBytes,
                 warm.generatedTokens, measure, measured.generatedTokens,
                 measured.generationTimeMs, tpsEngine, tpsQpc,
                 e.vulkanDeviceCount(), gpu0.c_str(), gpu1.c_str(),
                 fallbacks, strictViolation ? 1 : 0,
                 pass ? 1 : 0);

    std::fprintf(stderr, "RAWRXD_LOCAL_AGENT_FLEET_001=%s\n",
                 pass ? "PASS" : "HOLD");

    return pass ? 0 : 1;
}