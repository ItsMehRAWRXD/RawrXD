// ============================================================================
// rawrxd_inference_entry.cpp — RawrXD Audit → Local Model Inference Bridge
// ============================================================================
// Entry point for the full audit/context → inference loop:
//   RepositoryIndexer → ContextEngine → Local GGUF Model → Code Action
//
// Usage:
//   rawrxd.exe --audit D:\rawrxd
//   rawrxd.exe --audit D:\rawrxd --query "How do I fix the build?"
//   rawrxd.exe --audit D:\rawrxd --model D:\models\qwen2.5-7b-q8_0.gguf
//
// Phase: Context Generation Pipeline → Inference
// ============================================================================

#include "context/RepositoryIndexer.hpp"
#include "context/ContextEngine.hpp"
#include "inference/rawrxd_inference.h"
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <string>

using namespace RawrXD::Context;

// ============================================================================
// COMMAND LINE PARSING
// ============================================================================

struct LaunchConfig
{
    std::string auditPath;
    std::string modelPath;
    std::string userQuery;
    std::string outputPath;
    bool showHelp = false;
    bool verbose = false;
    size_t maxTokens = 4096;
    CompressionPolicy policy = CompressionPolicy::Semantic;
};

static void PrintUsage(const char* progName)
{
    std::cout << "RawrXD Audit → Inference Bridge\n"
              << "================================\n\n"
              << "Usage: " << progName << " [options]\n\n"
              << "Options:\n"
              << "  --audit <path>      Scan directory and generate context\n"
              << "  --model <path>      Path to GGUF model file\n"
              << "  --query <text>     User question for the model\n"
              << "  --output <path>     Write response to file (default: stdout)\n"
              << "  --tokens <n>       Max context tokens (default: 4096)\n"
              << "  --policy <mode>    Compression: verbose|standard|semantic|minimal\n"
              << "  --verbose           Show detailed scan progress\n"
              << "  --help              Show this help\n\n"
              << "Examples:\n"
              << "  " << progName << " --audit D:\\rawrxd --query \"Build errors?\"\n"
              << "  " << progName << " --audit D:\\rawrxd --model D:\\models\\qwen.gguf\n";
}

static LaunchConfig ParseArgs(int argc, char** argv)
{
    LaunchConfig cfg;
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h" || arg == "/?")
            cfg.showHelp = true;
        else if (arg == "--audit" && i + 1 < argc)
            cfg.auditPath = argv[++i];
        else if (arg == "--model" && i + 1 < argc)
            cfg.modelPath = argv[++i];
        else if (arg == "--query" && i + 1 < argc)
            cfg.userQuery = argv[++i];
        else if (arg == "--output" && i + 1 < argc)
            cfg.outputPath = argv[++i];
        else if (arg == "--tokens" && i + 1 < argc)
            cfg.maxTokens = std::stoul(argv[++i]);
        else if (arg == "--policy" && i + 1 < argc)
        {
            std::string p = argv[++i];
            if (p == "verbose") cfg.policy = CompressionPolicy::Verbose;
            else if (p == "standard") cfg.policy = CompressionPolicy::Standard;
            else if (p == "semantic") cfg.policy = CompressionPolicy::Semantic;
            else if (p == "minimal") cfg.policy = CompressionPolicy::Minimal;
        }
        else if (arg == "--verbose")
            cfg.verbose = true;
    }
    return cfg;
}

// ============================================================================
// INFERENCE BRIDGE
// ============================================================================

static bool InitializeInference(const std::string& modelPath)
{
    // TODO: Integrate with rawrxd_inference.h SafeInit and model loading
    // For now, report that we would load the model here
    std::cout << "[Inference] Model path: " << modelPath << "\n";
    std::cout << "[Inference] SafeInit would be called here\n";
    return true;
}

static std::string RunInference(const std::string& prompt, size_t maxTokens)
{
    // TODO: Replace with actual GGUF inference via rawrxd_inference.h
    // This is the integration point for the local model runtime
    std::cout << "[Inference] Sending " << prompt.size() << " chars to model...\n";
    
    // Placeholder: return a structured response
    std::ostringstream response;
    response << "## Analysis\n\n"
               << "Based on the project audit, here are the key findings:\n\n"
               << "1. **Build System**: CMake detected with Ninja generator\n"
               << "2. **Architecture**: Win32 native C++20 application\n"
               << "3. **Key Components**: IDE, inference engine, agent framework\n\n"
               << "## Recommendations\n\n"
               << "- Verify all ASM files compile with ml64.exe\n"
               << "- Ensure CMakeLists.txt references all new context/ files\n"
               << "- Run build with `ninja -C build_win32ide` to validate\n\n"
               << "*(This is a placeholder response — integrate with actual GGUF runtime)*";
    return response.str();
}

// ============================================================================
// MAIN ENTRY
// ============================================================================

int main(int argc, char** argv)
{
    LaunchConfig cfg = ParseArgs(argc, argv);

    if (cfg.showHelp || cfg.auditPath.empty())
    {
        PrintUsage(argv[0]);
        return cfg.showHelp ? 0 : 1;
    }

    std::cout << "========================================\n"
              << "RawrXD Audit → Inference Bridge\n"
              << "========================================\n\n";

    // Step 1: Index repository
    std::cout << "[1/4] Indexing repository: " << cfg.auditPath << "\n";
    auto start = std::chrono::steady_clock::now();

    IndexOptions opts;
    opts.includeCpp = true;
    opts.includeHeaders = true;
    opts.includeBuild = true;
    opts.includeDocs = true;
    opts.extractSymbols = true;
    opts.maxSymbols = 100;
    opts.maxIncludes = 50;
    opts.maxDependencies = 50;

    RepositoryIndex index = RepositoryIndexer::Index(cfg.auditPath, opts);

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    std::cout << "      Files: " << index.totalFiles << "\n"
              << "      Bytes: " << index.totalBytes << "\n"
              << "      C++:   " << index.cppFiles << "\n"
              << "      Headers: " << index.headerFiles << "\n"
              << "      Time:  " << elapsed << "ms\n\n";

    if (!index.issues.empty())
    {
        std::cout << "[Issues] " << index.issues.size() << " detected:\n";
        for (const auto& issue : index.issues)
            std::cout << "  - " << issue << "\n";
        std::cout << "\n";
    }

    // Step 2: Compress context
    std::cout << "[2/4] Compressing context (policy: ";
    switch (cfg.policy)
    {
        case CompressionPolicy::Verbose: std::cout << "verbose"; break;
        case CompressionPolicy::Standard: std::cout << "standard"; break;
        case CompressionPolicy::Semantic: std::cout << "semantic"; break;
        case CompressionPolicy::Minimal: std::cout << "minimal"; break;
    }
    std::cout << ", maxTokens: " << cfg.maxTokens << ")...\n";

    CompressedContext compressed = ContextEngine::Compress(index, cfg.policy, cfg.maxTokens);
    std::cout << "      Estimated tokens: " << compressed.totalTokenEstimate << "\n"
              << "      Chunks: " << compressed.chunks.size() << "\n\n";

    // Step 3: Build prompt
    std::cout << "[3/4] Building inference prompt...\n";
    std::string prompt = ContextEngine::BuildAuditPrompt(index, cfg.userQuery);
    std::cout << "      Prompt length: " << prompt.size() << " chars\n\n";

    if (cfg.verbose)
    {
        std::cout << "--- PROMPT PREVIEW ---\n"
                  << prompt.substr(0, std::min(prompt.size(), size_t(2000)))
                  << "\n... (truncated)\n"
                  << "--- END PREVIEW ---\n\n";
    }

    // Step 4: Run inference
    std::cout << "[4/4] Running inference...\n";
    std::string response;
    if (!cfg.modelPath.empty())
    {
        if (InitializeInference(cfg.modelPath))
            response = RunInference(prompt, cfg.maxTokens);
        else
            response = "[Error] Failed to initialize inference runtime.";
    }
    else
    {
        std::cout << "      (No model specified — using placeholder response)\n";
        response = RunInference(prompt, cfg.maxTokens);
    }

    // Output
    std::cout << "\n========================================\n"
              << "MODEL RESPONSE\n"
              << "========================================\n\n"
              << response << "\n\n";

    if (!cfg.outputPath.empty())
    {
        std::ofstream out(cfg.outputPath);
        if (out)
        {
            out << "# RawrXD Audit Report\n\n";
            out << "## Project Summary\n\n";
            out << ContextEngine::BuildAuditSummary(index) << "\n\n";
            out << "## Model Response\n\n";
            out << response << "\n";
            std::cout << "[Output] Written to: " << cfg.outputPath << "\n";
        }
        else
        {
            std::cerr << "[Error] Failed to write output file: " << cfg.outputPath << "\n";
        }
    }

    return 0;
}
