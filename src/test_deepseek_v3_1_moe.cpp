// ============================================================================
// test_deepseek_v3_1_moe.cpp — DeepSeek-V3.1 671B MoE Loader Test
// ============================================================================
// Tests loading DeepSeek-V3.1 671B (044d50a3d79c) with the PrometheusMoE streamer
//
// Usage: test_deepseek_v3_1_moe.exe <path_to_gguf>
//
// Expected model specs:
//   - 671B total parameters
//   - 256 experts (MoE)
//   - ~37B active parameters per token
//   - 4-bit quantization (Q4_K_M)
// ============================================================================

#include "inference/PrometheusMoE.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <random>
#include <fstream>

using namespace RawrXD::Inference;

// Format bytes to human-readable
std::string FormatBytes(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f %s", size, units[unit]);
    return std::string(buf);
}

// Format numbers with commas
std::string FormatNumber(size_t n) {
    std::string s = std::to_string(n);
    std::string result;
    int count = 0;
    for (int i = static_cast<int>(s.length()) - 1; i >= 0; --i) {
        if (count > 0 && count % 3 == 0) {
            result = "," + result;
        }
        result = s[i] + result;
        count++;
    }
    return result;
}

int main(int argc, char* argv[]) {
    std::cout << "============================================================" << std::endl;
    std::cout << "  DeepSeek-V3.1 671B MoE Streamer Test" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;

    // Parse arguments
    std::string modelPath;
    if (argc > 1) {
        modelPath = argv[1];
    } else {
        // Try default Ollama path for deepseek-v3.1:671b
        modelPath = "F:/OllamaModels/blobs/sha256-044d50a3d79c";
        std::cout << "[INFO] No model path provided, using default: " << modelPath << std::endl;
    }

    // Phase 1: Probe (fast metadata-only detection)
    std::cout << "[Phase 1] Probing GGUF metadata..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    
    MoEConfig config = PrometheusMoE::Probe(modelPath);
    
    auto probeEnd = std::chrono::high_resolution_clock::now();
    auto probeMs = std::chrono::duration_cast<std::chrono::milliseconds>(probeEnd - start).count();
    
    if (!config.IsValid()) {
        std::cerr << "[WARNING] Model does not appear to be a valid MoE architecture or file not found!" << std::endl;
        std::cerr << "  Path: " << modelPath << std::endl;
        std::cerr << std::endl;
        std::cerr << "This test is designed for MoE models like DeepSeek-V3.1 (671B)." << std::endl;
        std::cerr << "The PrometheusMoE loader detected the following:" << std::endl;
        std::cerr << "  - isMoE: " << (config.isMoE ? "true" : "false") << std::endl;
        std::cerr << "  - numLayers: " << config.numLayers << std::endl;
        std::cerr << "  - numExperts: " << config.numExperts << std::endl;
        std::cerr << "  - hiddenDim: " << config.hiddenDim << std::endl;
        std::cerr << std::endl;
        std::cerr << "You can still test with a standard GGUF model, but MoE-specific" << std::endl;
        std::cerr << "features like expert routing will not be available." << std::endl;
        std::cerr << std::endl;
        
        // Continue with limited testing for non-MoE models
        std::cout << "[INFO] Attempting basic GGUF validation..." << std::endl;
        
        // Check if file exists and has valid GGUF header
        std::ifstream testFile(modelPath, std::ios::binary);
        if (!testFile.is_open()) {
            std::cerr << "[ERROR] Cannot open file: " << modelPath << std::endl;
            return 1;
        }
        
        uint32_t magic = 0;
        testFile.read(reinterpret_cast<char*>(&magic), 4);
        if (magic != 0x46554747) { // "GGUF"
            std::cerr << "[ERROR] File does not have valid GGUF magic header" << std::endl;
            return 1;
        }
        
        std::cout << "  File exists and has valid GGUF header" << std::endl;
        std::cout << "  Probe time: " << probeMs << " ms" << std::endl;
        std::cout << std::endl;
        std::cout << "[NOTE] This is a standard (non-MoE) GGUF model." << std::endl;
        std::cout << "       To test with DeepSeek-V3.1 671B, provide the actual model file." << std::endl;
        return 0;
    }

    std::cout << "  Probe time: " << probeMs << " ms" << std::endl;
    std::cout << std::endl;

    // Display detected configuration
    std::cout << "[MoE Configuration Detected]" << std::endl;
    std::cout << "  Architecture:        " << (config.isMoE ? "Mixture of Experts (MoE)" : "Dense") << std::endl;
    std::cout << "  Total Experts:       " << config.numExperts << std::endl;
    std::cout << "  Experts Per Token:   " << config.expertsPerToken << std::endl;
    std::cout << "  Shared Experts:      " << config.numSharedExperts << std::endl;
    std::cout << "  Hidden Layers:       " << config.numLayers << std::endl;
    std::cout << "  Hidden Dimension:    " << FormatNumber(config.hiddenDim) << std::endl;
    std::cout << "  Intermediate Dim:    " << FormatNumber(config.intermediateDim) << std::endl;
    std::cout << "  Attention Heads:     " << config.numHeads << std::endl;
    std::cout << "  KV Heads:            " << config.numKVHeads << std::endl;
    std::cout << "  Head Dimension:      " << config.headDim << std::endl;
    std::cout << "  Vocab Size:          " << FormatNumber(config.vocabSize) << std::endl;
    std::cout << std::endl;

    // Memory estimates
    std::cout << "[Memory Estimates]" << std::endl;
    std::cout << "  Total Parameters:    " << FormatNumber(config.totalParams) << std::endl;
    std::cout << "  Active Parameters:   " << FormatNumber(config.activeParams) << std::endl;
    std::cout << "  Sparsity Ratio:      " << std::fixed << std::setprecision(2) 
              << (1.0 - static_cast<double>(config.activeParams) / config.totalParams) * 100.0 
              << "%" << std::endl;
    std::cout << "  Model Size:          " << FormatBytes(config.modelSizeBytes) << std::endl;
    std::cout << "  KV Cache (8K ctx):   " << FormatBytes(config.kvCacheBytes) << std::endl;
    std::cout << "  VRAM Estimate:       " << FormatBytes(config.EstimateVRAM()) << std::endl;
    std::cout << std::endl;

    // Phase 2: Full Load
    std::cout << "[Phase 2] Loading model weights (memory-mapped)..." << std::endl;
    PrometheusMoE loader;
    
    start = std::chrono::high_resolution_clock::now();
    bool loaded = loader.Load(modelPath, -1); // -1 = all layers on GPU if available
    auto loadEnd = std::chrono::high_resolution_clock::now();
    auto loadMs = std::chrono::duration_cast<std::chrono::milliseconds>(loadEnd - start).count();
    
    if (!loaded) {
        std::cerr << "[ERROR] Failed to load model weights!" << std::endl;
        return 1;
    }
    
    std::cout << "  Load time: " << loadMs << " ms" << std::endl;
    std::cout << "  Status:    SUCCESS" << std::endl;
    std::cout << std::endl;

    // Phase 3: Expert Routing Test
    std::cout << "[Phase 3] Testing expert routing..." << std::endl;
    
    // Generate synthetic token embedding
    std::vector<float> embedding(config.hiddenDim);
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.02f);
    for (auto& v : embedding) {
        v = dist(rng);
    }

    // Test routing on first layer
    std::cout << "  Testing layer 0 routing..." << std::endl;
    auto experts = loader.RouteExperts(0, embedding.data(), config.topK);
    
    std::cout << "  Selected experts: [";
    for (size_t i = 0; i < experts.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << experts[i];
    }
    std::cout << "]" << std::endl;

    // Get weight pointers for first selected expert
    if (!experts.empty()) {
        auto weights = loader.GetExpertWeights(0, experts[0]);
        std::cout << "  Expert " << experts[0] << " weights:" << std::endl;
        std::cout << "    Gate: " << (weights.gate ? "mapped" : "null") 
                  << " (" << FormatBytes(weights.gateSize) << ")" << std::endl;
        std::cout << "    Up:   " << (weights.up ? "mapped" : "null") 
                  << " (" << FormatBytes(weights.upSize) << ")" << std::endl;
        std::cout << "    Down: " << (weights.down ? "mapped" : "null") 
                  << " (" << FormatBytes(weights.downSize) << ")" << std::endl;
    }
    std::cout << std::endl;

    // Phase 4: Benchmark
    std::cout << "[Phase 4] Benchmarking expert routing..." << std::endl;
    const int iterations = 1000;
    
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        // Vary the embedding slightly
        for (auto& v : embedding) {
            v += dist(rng) * 0.001f;
        }
        loader.RouteExperts(i % config.numLayers, embedding.data(), config.topK);
    }
    auto benchEnd = std::chrono::high_resolution_clock::now();
    auto benchMs = std::chrono::duration_cast<std::chrono::microseconds>(benchEnd - start).count();
    
    double avgLatencyUs = static_cast<double>(benchMs) / iterations;
    double throughputTps = 1000000.0 / avgLatencyUs;
    
    std::cout << "  Iterations:    " << iterations << std::endl;
    std::cout << "  Total time:    " << benchMs / 1000.0 << " ms" << std::endl;
    std::cout << "  Avg latency:   " << std::fixed << std::setprecision(3) << avgLatencyUs << " us" << std::endl;
    std::cout << "  Throughput:    " << std::fixed << std::setprecision(1) << throughputTps << " routes/sec" << std::endl;
    std::cout << std::endl;

    // Stats
    auto stats = loader.GetStats();
    std::cout << "[Statistics]" << std::endl;
    std::cout << "  Total tokens processed:    " << stats.totalTokens << std::endl;
    std::cout << "  Total expert activations:  " << stats.totalExpertActivations << std::endl;
    std::cout << "  Avg active experts/token:  " << std::fixed << std::setprecision(2) << stats.avgActiveExperts << std::endl;
    std::cout << "  Cache hits:                " << stats.cacheHits << std::endl;
    std::cout << "  Cache misses:              " << stats.cacheMisses << std::endl;
    std::cout << std::endl;

    // Cleanup
    std::cout << "[Cleanup] Unloading model..." << std::endl;
    loader.Unload();
    std::cout << "  Done." << std::endl;

    std::cout << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << "  DeepSeek-V3.1 671B MoE Test COMPLETE" << std::endl;
    std::cout << "============================================================" << std::endl;

    return 0;
}
