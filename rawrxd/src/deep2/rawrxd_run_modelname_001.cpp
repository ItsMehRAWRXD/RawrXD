// rawrxd_run_modelname_001.cpp
// ONE_LOCAL_MODEL_AUTHORITY: resolve model by name or path, load through
// Deep2Engine, stream tokens to stdout, emit receipt to stderr.
#include "rawrxd_run_modelname_001.h"
#include "Deep2Engine.h"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>
#include <chrono>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Model resolution
// ---------------------------------------------------------------------------
// Accepts:
//   - absolute path to a .gguf file
//   - relative path to a .gguf file (resolved from cwd)
//   - bare model name: searched in RAWRXD_MODEL_DIR env var, then common dirs
static std::string resolveModelPath(const std::string& nameOrPath) {
    // Direct path
    if (nameOrPath.size() > 5 &&
        nameOrPath.substr(nameOrPath.size() - 5) == ".gguf") {
        fs::path p(nameOrPath);
        if (fs::exists(p)) return p.string();
        // Try relative to cwd
        fs::path rel = fs::current_path() / p;
        if (fs::exists(rel)) return rel.string();
    }

    // Search directories
    std::vector<fs::path> searchDirs;

    const char* modelDir = std::getenv("RAWRXD_MODEL_DIR");
    if (modelDir && modelDir[0]) searchDirs.emplace_back(modelDir);

    // Common local model locations
    searchDirs.emplace_back("F:\\models");
    searchDirs.emplace_back("C:\\models");
    searchDirs.emplace_back("D:\\models");

    const char* home = std::getenv("USERPROFILE");
    if (home) {
        searchDirs.emplace_back(fs::path(home) / ".cache" / "lm-studio" / "models");
        searchDirs.emplace_back(fs::path(home) / "models");
    }

    for (const fs::path& dir : searchDirs) {
        if (!fs::exists(dir)) continue;
        // Exact filename match
        fs::path exact = dir / (nameOrPath + ".gguf");
        if (fs::exists(exact)) return exact.string();
        // Fuzzy: walk dir, find first .gguf whose stem contains nameOrPath
        std::error_code ec;
        for (const auto& entry : fs::recursive_directory_iterator(dir, ec)) {
            if (ec) break;
            if (!entry.is_regular_file()) continue;
            const std::string stem = entry.path().stem().string();
            const std::string ext  = entry.path().extension().string();
            if (ext != ".gguf") continue;
            // Case-insensitive substring match
            std::string stemLow = stem, nameLow = nameOrPath;
            for (char& c : stemLow) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char& c : nameLow) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (stemLow.find(nameLow) != std::string::npos)
                return entry.path().string();
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------
int rawrxd_run_modelname_001(const char* modelNameOrPath,
                              const char* prompt,
                              uint32_t    maxTokens,
                              bool        vulkanEnabled,
                              bool        strictVulkan) {
    if (!modelNameOrPath || !modelNameOrPath[0]) {
        std::fprintf(stderr, "[rawr run] ERROR: no model specified\n");
        return 1;
    }
    if (!prompt || !prompt[0]) {
        std::fprintf(stderr, "[rawr run] ERROR: no prompt specified\n");
        return 1;
    }

    // --- Resolve ---
    std::fprintf(stderr, "[rawr run] MODEL_RESOLUTION: resolving '%s'\n", modelNameOrPath);
    std::fflush(stderr);

    const std::string ggufPath = resolveModelPath(modelNameOrPath);
    if (ggufPath.empty()) {
        std::fprintf(stderr,
            "[rawr run] MODEL_RESOLUTION=FAIL  could not locate '%s'\n"
            "  Set RAWRXD_MODEL_DIR or pass an absolute .gguf path.\n",
            modelNameOrPath);
        return 1;
    }
    std::fprintf(stderr, "[rawr run] MODEL_RESOLUTION=PASS  path=%s\n", ggufPath.c_str());
    std::fflush(stderr);

    // --- Engine ---
    Deep2::Deep2Engine engine;
    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen   = 4096;
    cfg.useKVCache  = true;
    cfg.useThreadPool = true;
    cfg.numThreads  = 0; // auto

    if (!engine.initialize(cfg)) {
        std::fprintf(stderr, "[rawr run] ENGINE_INIT=FAIL\n");
        return 1;
    }

    // --- Vulkan ---
    if (vulkanEnabled) {
        engine.enableVulkan(true);
        std::fprintf(stderr, "[rawr run] VULKAN=ENABLED\n");
    }
    if (strictVulkan) {
        if (!engine.isVulkanInitialized()) {
            std::fprintf(stderr,
                "[rawr run] STRICT_GPU_VIOLATION "
                "enabled=%d initialized=%d\n",
                engine.isVulkanEnabled() ? 1 : 0,
                engine.isVulkanInitialized() ? 1 : 0);
            return 1;
        }
    }

    // --- Load ---
    std::fprintf(stderr, "[rawr run] MODEL_LOAD: loading...\n");
    std::fflush(stderr);

    Deep2::ModelLoadDiag diag{};
    const auto t0 = std::chrono::steady_clock::now();
    if (!engine.loadModel(ggufPath, &diag)) {
        std::fprintf(stderr,
            "[rawr run] MODEL_LOAD=FAIL  stage=%s  msg=%s\n",
            diag.stageName.c_str(), diag.message.c_str());
        return 1;
    }
    const double loadMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    std::fprintf(stderr, "[rawr run] MODEL_LOAD=PASS  %.0f ms\n", loadMs);
    std::fflush(stderr);

    // --- Generate ---
    std::fprintf(stderr, "[rawr run] GENERATE: streaming...\n");
    std::fflush(stderr);

    Deep2::GenerationOptions opts{};
    opts.maxTokens   = maxTokens ? maxTokens : 512;
    opts.temperature = 0.0f; // greedy
    opts.topK        = 1;

    uint64_t tokenCount = 0;
    const auto tGen0 = std::chrono::steady_clock::now();

    Deep2::GenerationResult result = engine.generateStream(
        prompt, opts,
        [&](int32_t /*tokenId*/, const std::string& piece) -> bool {
            std::fputs(piece.c_str(), stdout);
            std::fflush(stdout);
            ++tokenCount;
            return true; // continue
        });

    const double genMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - tGen0).count();

    std::fputc('\n', stdout);
    std::fflush(stdout);

    // --- Receipt ---
    const double tps = genMs > 0.0 ? (tokenCount / (genMs / 1000.0)) : 0.0;
    std::fprintf(stderr,
        "\n[rawr run] RECEIPT\n"
        "  MODEL=%s\n"
        "  PROMPT_TOKENS=%llu\n"
        "  GENERATED_TOKENS=%llu\n"
        "  WALL_MS=%.1f\n"
        "  TPS=%.3f\n"
        "  COMPLETED=%s\n",
        ggufPath.c_str(),
        static_cast<unsigned long long>(result.promptTokens),
        static_cast<unsigned long long>(result.generatedTokens),
        genMs,
        tps,
        result.completed ? "YES" : "NO");
    std::fflush(stderr);

    return result.completed ? 0 : 1;
}
