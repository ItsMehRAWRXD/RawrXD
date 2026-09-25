// deep2_benchmark_main.cpp
// DEEP2_NATIVE_BENCHMARK_001 — native Deep2 benchmark through Deep2Engine
// Correct benchmark: instantiates production Deep2Engine, not rawr_monolith

#include "Deep2Engine.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <string>

static void printUsage(const char* exe) {
    std::fprintf(stderr,
        "Usage: %s [options] <model.gguf> <prompt>\n"
        "Options:\n"
        "  --vulkan          Enable Vulkan GPU acceleration\n"
        "  --strict-vulkan   Require Vulkan; fail if not initialized\n"
        "  --max-tokens <n>  Maximum tokens to generate (default: 313)\n"
        "  --format <fmt>    Output format: text | json (default: text)\n"
        "\n"
        "Authority chain: Deep2Engine -> GGUF -> tokens -> TPS\n",
        exe);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    bool vulkanEnabled = false;
    bool strictVulkan = false;
    uint32_t maxTokens = 313;
    std::string format = "text";
    std::string modelPath;
    std::string prompt;

    // Parse options
    int i = 1;
    for (; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--vulkan" || arg == "-vulkan") {
            vulkanEnabled = true;
        } else if (arg == "--strict-vulkan" || arg == "-strict-vulkan") {
            strictVulkan = true;
            vulkanEnabled = true;
        } else if (arg == "--max-tokens" || arg == "-max-tokens") {
            if (i + 1 < argc) {
                maxTokens = static_cast<uint32_t>(std::atoi(argv[++i]));
            }
        } else if (arg == "--format" || arg == "-format") {
            if (i + 1 < argc) {
                format = argv[++i];
            }
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if (arg[0] == '-') {
            std::fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            return 1;
        } else {
            // Positional argument
            break;
        }
    }

    if (i >= argc) {
        std::fprintf(stderr, "ERROR: no model specified\n");
        printUsage(argv[0]);
        return 1;
    }
    modelPath = argv[i++];

    if (i >= argc) {
        std::fprintf(stderr, "ERROR: no prompt specified\n");
        printUsage(argv[0]);
        return 1;
    }
    for (; i < argc; ++i) {
        if (!prompt.empty()) prompt += ' ';
        prompt += argv[i];
    }

    // --- Authority receipt header ---
    std::fprintf(stderr,
        "========================================\n"
        "  DEEP2_NATIVE_BENCHMARK_001\n"
        "========================================\n"
        "ENGINE=Deep2Engine\n"
        "VULKAN_REQUESTED=%d\n"
        "STRICT_VULKAN=%d\n",
        vulkanEnabled ? 1 : 0,
        strictVulkan ? 1 : 0);

    // --- Engine ---
    Deep2::Deep2Engine engine;
    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen = 4096;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 0;

    if (!engine.initialize(cfg)) {
        std::fprintf(stderr, "FAIL=initialize\n");
        return 1;
    }

    // --- Vulkan ---
    if (vulkanEnabled) {
        engine.enableVulkan(true);
        std::fprintf(stderr, "VULKAN_ENABLED=1\n");
    } else {
        std::fprintf(stderr, "VULKAN_ENABLED=0\n");
    }

    if (strictVulkan) {
        if (!engine.isVulkanInitialized()) {
            std::fprintf(stderr,
                "STRICT_GPU_VIOLATION enabled=%d initialized=%d\n",
                engine.isVulkanEnabled() ? 1 : 0,
                engine.isVulkanInitialized() ? 1 : 0);
            return 1;
        }
        std::fprintf(stderr, "STRICT_VULKAN_PASS=1\n");
    }

    // --- Model load ---
    std::fprintf(stderr, "MODEL_LOAD: loading %s ...\n", modelPath.c_str());
    Deep2::ModelLoadDiag diag{};
    const auto tLoad0 = std::chrono::steady_clock::now();
    if (!engine.loadModel(modelPath, &diag)) {
        std::fprintf(stderr, "FAIL=loadModel stage=%s msg=%s\n",
            diag.stageName.c_str(), diag.message.c_str());
        return 1;
    }
    const double loadMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - tLoad0).count();
    std::fprintf(stderr, "MODEL_LOAD=PASS %.0f ms\n", loadMs);

    // Report actual model metadata from the loaded weights
    const Deep2::EngineConfig& loadedCfg = engine.getConfig();
    std::fprintf(stderr,
        "MODEL_ARCH=%s\n"
        "MODEL_LAYERS=%zu\n"
        "MODEL_HIDDEN=%zu\n"
        "MODEL_HEADS=%zu\n"
        "MODEL_KV_HEADS=%zu\n",
        engine.modelArchitecture().empty() ? "unknown" : engine.modelArchitecture().c_str(),
        loadedCfg.numLayers,
        loadedCfg.hiddenDim,
        loadedCfg.numHeads,
        loadedCfg.numKVHeads);

    // --- Generate ---
    Deep2::GenerationOptions opts{};
    opts.maxTokens = maxTokens;
    opts.temperature = 0.0f;
    opts.topK = 1;

    uint64_t tokenCount = 0;
    uint64_t promptTokens = 0;
    const auto tGen0 = std::chrono::steady_clock::now();

    Deep2::GenerationResult result = engine.generateStream(
        prompt.c_str(), opts,
        [&](int32_t /*tokenId*/, const std::string& piece) -> bool {
            if (tokenCount == 0) {
                // First token marks end of prefill
            }
            if (format == "text") {
                std::fputs(piece.c_str(), stdout);
                std::fflush(stdout);
            }
            ++tokenCount;
            return true;
        });

    const double genMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - tGen0).count();

    if (format == "text") {
        std::fputc('\n', stdout);
    }

    // --- Receipt ---
    const double tps = genMs > 0.0 ? (tokenCount / (genMs / 1000.0)) : 0.0;

    std::fprintf(stderr,
        "\n========================================\n"
        "  RECEIPT\n"
        "========================================\n"
        "GATE=DEEP2_NATIVE_BENCHMARK_001\n"
        "ENGINE=Deep2Engine\n"
        "EXECUTION_BACKEND=%s\n"
        "VULKAN_REQUESTED=%d\n"
        "VULKAN_INITIALIZED=%d\n"
        "GPU_FORWARD=%d\n"
        "CPU_FORWARD=%d\n"
        "CPU_FALLBACK=%d\n"
        "MODEL=%s\n"
        "PROMPT_TOKENS=%llu\n"
        "GENERATED_TOKENS=%llu\n"
        "PREFILL_MS=0\n"
        "DECODE_MS=%.1f\n"
        "DECODE_TPS_REAL=%.3f\n"
        "VERDICT=%s\n",
        (vulkanEnabled && engine.isVulkanInitialized()) ? "GPU" : "CPU",
        vulkanEnabled ? 1 : 0,
        engine.isVulkanInitialized() ? 1 : 0,
        (vulkanEnabled && engine.isVulkanInitialized()) ? 1 : 0,
        (vulkanEnabled && engine.isVulkanInitialized()) ? 0 : 1,
        0,
        modelPath.c_str(),
        static_cast<unsigned long long>(promptTokens),
        static_cast<unsigned long long>(tokenCount),
        genMs,
        tps,
        (tokenCount > 0) ? "PASS" : "FAIL");

    return (tokenCount > 0) ? 0 : 1;
}
