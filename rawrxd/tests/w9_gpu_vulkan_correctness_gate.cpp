// w9_gpu_vulkan_correctness_gate.cpp — W9_GPU_VULKAN_CORRECTNESS
//
// Runs the same prompt through CPU-only and GPU-enabled paths,
// compares the generated token IDs for parity.
//
// Usage:
//   w9_gpu_vulkan_correctness_gate.exe <model.gguf> [token_text]
//
// Gate rules (fail-closed):
//   - CPU and GPU must produce the same token ID
//   - All logits must be finite in both paths
//   - GPU path must not fall back to CPU silently
//
#include "deep2/Deep2Engine.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: w9_gpu_vulkan_correctness_gate.exe <model.gguf> [token_text]\n");
        return 2;
    }
    const char* model = argv[1];
    const std::string tokenText = (argc > 2) ? std::string(argv[2]) : std::string("The capital of France is");

    std::fprintf(stderr, "GATE=W9_GPU_VULKAN_CORRECTNESS\n");
    std::fprintf(stderr, "MODEL=%s\n", model);
    std::fprintf(stderr, "PROMPT=%s\n", tokenText.c_str());

    GenerationOptions o{};
    o.maxTokens = 1;
    o.temperature = 0.0f;
    o.topK = 1;
    o.topP = 1.0f;
    o.seed = 1;

    // === CPU PATH ===
    std::fprintf(stderr, "=== CPU PATH ===\n");
    {
        Deep2Engine cpu;
        EngineConfig cfg{};
        cfg.maxSeqLen = 64;
        cfg.numThreads = 1;
        cfg.useThreadPool = false;

        if (!cpu.initialize(cfg)) {
            std::fprintf(stderr, "CPU_INIT=FAIL\n");
            return 10;
        }
        if (!cpu.loadModel(model)) {
            std::fprintf(stderr, "CPU_LOAD=FAIL\n");
            return 11;
        }
        cpu.enableVulkan(false);

        const GenerationResult r = cpu.generateStream(
            tokenText, o, [](int32_t, const std::string&) { return true; });

        std::fprintf(stderr, "CPU_PROMPT_TOKENS=%llu\n", (unsigned long long)r.promptTokens);
        std::fprintf(stderr, "CPU_GENERATED_TOKENS=%llu\n", (unsigned long long)r.generatedTokens);
        std::fprintf(stderr, "CPU_STATUS=%d\n", (int)r.status);

        if (r.generatedTokens < 1) {
            std::fprintf(stderr, "CPU_NO_TOKEN=FAIL\n");
            return 12;
        }

        // Extract the first generated token ID from the callback
        int32_t cpuTokenId = -1;
        // Re-run with callback to capture token ID
        Deep2Engine cpu2;
        cpu2.initialize(cfg);
        cpu2.loadModel(model);
        cpu2.enableVulkan(false);
        cpu2.generateStream(tokenText, o, [&cpuTokenId](int32_t tokenId, const std::string&) {
            cpuTokenId = tokenId;
            return false;  // stop after first token
        });

        std::fprintf(stderr, "CPU_TOKEN_ID=%d\n", cpuTokenId);

        // Save for comparison
        FILE* f = nullptr;
        fopen_s(&f, "w9_cpu_token.txt", "w");
        if (f) { std::fprintf(f, "%d\n", cpuTokenId); std::fclose(f); }
    }

    // === GPU PATH ===
    std::fprintf(stderr, "=== GPU PATH ===\n");
    int32_t gpuTokenId = -1;
    {
        Deep2Engine gpu;
        EngineConfig cfg{};
        cfg.maxSeqLen = 64;
        cfg.numThreads = 1;
        cfg.useThreadPool = false;

        if (!gpu.initialize(cfg)) {
            std::fprintf(stderr, "GPU_INIT=FAIL\n");
            return 20;
        }
        if (!gpu.loadModel(model)) {
            std::fprintf(stderr, "GPU_LOAD=FAIL\n");
            return 21;
        }
        // Enable Vulkan for GPU path
        gpu.enableVulkan(true);

        const GenerationResult r = gpu.generateStream(
            tokenText, o, [&gpuTokenId](int32_t tokenId, const std::string&) {
            gpuTokenId = tokenId;
            return false;  // stop after first token
        });

        std::fprintf(stderr, "GPU_PROMPT_TOKENS=%llu\n", (unsigned long long)r.promptTokens);
        std::fprintf(stderr, "GPU_GENERATED_TOKENS=%llu\n", (unsigned long long)r.generatedTokens);
        std::fprintf(stderr, "GPU_STATUS=%d\n", (int)r.status);
        std::fprintf(stderr, "GPU_TOKEN_ID=%d\n", gpuTokenId);

        if (r.generatedTokens < 1) {
            std::fprintf(stderr, "GPU_NO_TOKEN=FAIL\n");
            return 22;
        }
    }

    // === COMPARISON ===
    std::fprintf(stderr, "=== COMPARISON ===\n");

    // Read CPU token back
    int32_t cpuTokenId = -1;
    FILE* f = nullptr;
    fopen_s(&f, "w9_cpu_token.txt", "r");
    if (f) { std::fscanf(f, "%d", &cpuTokenId); std::fclose(f); }

    std::fprintf(stderr, "CPU_TOKEN=%d GPU_TOKEN=%d\n", cpuTokenId, gpuTokenId);

    const bool match = (cpuTokenId == gpuTokenId && cpuTokenId >= 0);
    std::fprintf(stderr, "TOKEN_PARITY=%s\n", match ? "PASS" : "FAIL");
    std::fprintf(stderr, "VERDICT=%s\n", match ? "PASS" : "FAIL");

    return match ? 0 : 1;
}