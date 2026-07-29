// ============================================================================
// TestUniversalRuntime.cpp
// ============================================================================
// Demonstrates the "compile once, execute many" pipeline:
//   ANY FILE -> Sniff -> Parse -> CanonicalModelGraph -> RuntimeImage
//
// After compilation, ExecuteNextToken() has ZERO format/architecture checks.
//
// Build: cl /EHsc /O2 /std:c++17 TestUniversalRuntime.cpp ^
//          UniversalRuntimeBridge.cpp UniversalHeaderSniffer.cpp ^
//          /Isrc /Isrc/core /Isrc/core/execution
// ============================================================================

#include <iostream>
#include <iomanip>
#include <chrono>
#include "../runtime/UniversalRuntimeBridge.hpp"

using namespace RawrXD;

void PrintImageSummary(const RuntimeImage& img) {
    std::cout << "========================================" << std::endl;
    std::cout << "Runtime Image Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Source:     " << img.sourcePath << std::endl;
    std::cout << "Format:     " << static_cast<uint32_t>(img.sourceFormat) << std::endl;
    std::cout << "Compiled:   " << (img.compiled.load() ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
    
    std::cout << "--- Canonical Model Graph ---" << std::endl;
    std::cout << "Architecture:   " << img.graph.architecture << std::endl;
    std::cout << "Hidden size:    " << img.graph.hiddenSize << std::endl;
    std::cout << "Layers:         " << img.graph.numLayers << std::endl;
    std::cout << "Vocab size:     " << img.graph.vocabSize << std::endl;
    std::cout << "Max context:    " << img.graph.maxContext << std::endl;
    std::cout << "MoE:            " << (img.graph.isMoE ? "YES" : "NO") << std::endl;
    if (img.graph.isMoE) {
        std::cout << "  Experts:     " << img.graph.numExperts << std::endl;
        std::cout << "  Active:      " << img.graph.numActiveExperts << std::endl;
        std::cout << "  Shared:      " << img.graph.numSharedExperts << std::endl;
    }
    std::cout << "Tensors:        " << img.graph.tensors.size() << std::endl;
    std::cout << std::endl;
    
    std::cout << "--- Kernel Table ---" << std::endl;
    std::cout << "Bindings:       " << img.kernelTable.size() << std::endl;
    for (size_t i = 0; i < std::min(img.kernelTable.size(), size_t(5)); ++i) {
        const auto& kb = img.kernelTable[i];
        std::cout << "  [" << i << "] " << kb.operationName 
                  << " -> " << kb.kernelName 
                  << " (" << kb.backendName << ")"
                  << " hotpatch=" << kb.hotpatchHandle << std::endl;
    }
    if (img.kernelTable.size() > 5) {
        std::cout << "  ... (" << img.kernelTable.size() - 5 << " more)" << std::endl;
    }
    std::cout << std::endl;
    
    std::cout << "--- Scheduler Hints ---" << std::endl;
    std::cout << "Sliding window: " << (img.hints.useSlidingWindow ? "YES" : "NO");
    if (img.hints.useSlidingWindow) std::cout << " (" << img.hints.slidingWindowSize << ")";
    std::cout << std::endl;
    std::cout << "Medusa:         " << (img.hints.useMedusa ? "YES" : "NO");
    if (img.hints.useMedusa) std::cout << " (" << img.hints.medusaHeads << " heads)";
    std::cout << std::endl;
    std::cout << "Speculative:    " << (img.hints.useSpeculativeDecode ? "YES" : "NO") << std::endl;
    std::cout << "Expert cache:   " << (img.hints.useExpertCache ? "YES" : "NO");
    if (img.hints.useExpertCache) std::cout << " (" << img.hints.expertCacheCapacity << ")";
    std::cout << std::endl;
    std::cout << "NVMe streaming: " << (img.hints.useNVMeStreaming ? "YES" : "NO") << std::endl;
    std::cout << "Warmup:         " << (img.hints.useWarmup ? "YES" : "NO") << std::endl;
    std::cout << "Paged KV:       " << (img.hints.usePagedKV ? "YES" : "NO");
    if (img.hints.usePagedKV) std::cout << " (" << img.hints.pagedKVBlockSize << "/block)";
    std::cout << std::endl;
    std::cout << std::endl;
}

void BenchmarkHotPath(RuntimeImage& img, int numTokens) {
    std::cout << "--- Hot-Path Benchmark (" << numTokens << " tokens) ---" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    int32_t token = 0;
    for (int i = 0; i < numTokens; ++i) {
        // HOT PATH: This is all that runs during inference.
        // No format checks. No architecture detection. No kernel lookup.
        // No quantization dispatch. No graph construction.
        token = img.ExecuteNextToken({static_cast<uint32_t>(token)});
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    double ms = us / 1000.0;
    double tps = numTokens / (ms / 1000.0);
    
    std::cout << "Total time: " << ms << " ms" << std::endl;
    std::cout << "Per token:  " << (us / numTokens) << " us" << std::endl;
    std::cout << "Throughput: " << tps << " tokens/sec" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "RawrXD Universal Runtime - Compile Once, Execute Many" << std::endl;
    std::cout << "====================================================" << std::endl;
    std::cout << std::endl;
    
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <model_file> [num_tokens]" << std::endl;
        std::cout << std::endl;
        std::cout << "The file extension is ignored. Format is detected by magic bytes." << std::endl;
        return 1;
    }
    
    std::string path = argv[1];
    int numTokens = (argc > 2) ? std::atoi(argv[2]) : 100;
    
    // Stage 1: Load + compile (ALL expensive decisions happen here)
    std::cout << "[1] Loading and compiling: " << path << std::endl;
    auto image = UniversalRuntime::Instance().Load(path);
    
    if (!image) {
        std::cout << "[ERROR] Failed to compile runtime image" << std::endl;
        return 1;
    }
    
    // Print the compiled image
    PrintImageSummary(*image);
    
    // Stage 2: Hot-path execution (ZERO format/architecture checks)
    std::cout << "[2] Executing hot path..." << std::endl;
    BenchmarkHotPath(*image, numTokens);
    
    // Stage 3: Demonstrate hotpatch (swap without recompiling)
    std::cout << "[3] Hotpatch recompile (no full rebuild)..." << std::endl;
    UniversalRuntime::Instance().GetCompiler().HotpatchRecompile(*image, "test_patch");
    std::cout << "    Hotpatch applied (no-op in demo)" << std::endl;
    std::cout << std::endl;
    
    // Stage 4: List loaded models
    std::cout << "[4] Loaded models:" << std::endl;
    for (const auto& p : UniversalRuntime::Instance().ListLoaded()) {
        std::cout << "    - " << p << std::endl;
    }
    std::cout << std::endl;
    
    std::cout << "========================================" << std::endl;
    std::cout << "Pipeline complete." << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "All format/architecture/quant/kernel decisions" << std::endl;
    std::cout << "were made ONCE at compile time." << std::endl;
    std::cout << "The hot path (ExecuteNextToken) has ZERO branching." << std::endl;
    
    return 0;
}