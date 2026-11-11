// ============================================================================
// Tree Attention Benchmark Suite
// Reproducible performance validation for VAL-032
// ============================================================================

#include "../src/inference/RawrXD_TreeAttention.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <fstream>
#include <json/json.h>

using namespace RawrXD::Inference;

// ============================================================================
// Benchmark Configuration
// ============================================================================

struct BenchmarkConfig {
    uint32_t iterations = 1000;
    uint32_t warmupIterations = 100;
    uint32_t headDim = 64;
    uint32_t numHeads = 32;
    bool useAVX512 = true;
    bool outputJSON = true;
    std::string outputFile = "tree_attention_benchmark.json";
};

// ============================================================================
// Hardware Detection
// ============================================================================

struct CPUInfo {
    std::string vendor;
    std::string model;
    uint32_t cores;
    uint32_t threads;
    bool hasAVX512;
    bool hasAVX2;
    uint32_t cacheL1;
    uint32_t cacheL2;
    uint32_t cacheL3;
};

CPUInfo DetectCPU() {
    CPUInfo info;
    info.hasAVX512 = TreeAttention_HasAVX512();
    info.hasAVX2 = true;  // Assume AVX2 for x64
    
    // Get CPU info from Windows
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info.cores = sysInfo.dwNumberOfProcessors;
    info.threads = sysInfo.dwNumberOfProcessors;
    
    // Cache sizes (simplified)
    info.cacheL1 = 32;
    info.cacheL2 = 256;
    info.cacheL3 = 16384;
    
    return info;
}

// ============================================================================
// Benchmark Functions
// ============================================================================

struct BenchmarkResult {
    double avgLatencyUs;
    double minLatencyUs;
    double maxLatencyUs;
    double stdDevUs;
    double throughputTokensPerSec;
    double totalTimeMs;
    uint64_t iterations;
};

BenchmarkResult RunBenchmark(const BenchmarkConfig& config) {
    const uint32_t numNodes = 16;  // 4x4 tree
    const uint32_t headDim = config.headDim;
    
    // Allocate aligned memory
    std::vector<float> Q(numNodes * headDim);
    std::vector<float> K(numNodes * headDim);
    std::vector<float> V(numNodes * headDim);
    std::vector<float> output(numNodes * headDim);
    std::vector<uint8_t> mask(numNodes * numNodes);
    
    // Initialize with random data
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (auto& v : Q) v = dist(rng);
    for (auto& v : K) v = dist(rng);
    for (auto& v : V) v = dist(rng);
    for (auto& v : mask) v = (rng() % 2) ? 1 : 0;
    
    // Create kernel
    TreeAttentionKernel* kernel = config.useAVX512 ? 
        CreateTreeAttentionKernel() : new TreeAttentionKernel();
    
    kernel->Initialize(64, 64, 32);
    
    // Prepare params
    TreeAttentionParams params;
    params.query = Q.data();
    params.key = K.data();
    params.value = V.data();
    params.causalMask = mask.data();
    params.output = output.data();
    params.numNodes = numNodes;
    params.prefixLen = 0;
    params.numHeads = config.numHeads;
    params.headDim = headDim;
    params.softmaxScale = 1.0f / std::sqrt(static_cast<float>(headDim));
    params.useFP16 = false;
    
    // Warmup
    std::cout << "Warming up (" << config.warmupIterations << " iterations)...\n";
    for (uint32_t i = 0; i < config.warmupIterations; i++) {
        kernel->Forward(params);
    }
    
    // Benchmark
    std::cout << "Running benchmark (" << config.iterations << " iterations)...\n";
    std::vector<double> latencies;
    latencies.reserve(config.iterations);
    
    auto totalStart = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < config.iterations; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        kernel->Forward(params);
        auto end = std::chrono::high_resolution_clock::now();
        
        double latencyUs = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count() / 1000.0;
        latencies.push_back(latencyUs);
    }
    
    auto totalEnd = std::chrono::high_resolution_clock::now();
    
    // Calculate statistics
    BenchmarkResult result;
    result.iterations = config.iterations;
    result.totalTimeMs = std::chrono::duration_cast<std::chrono::microseconds>(totalEnd - totalStart).count() / 1000.0;
    
    double sum = 0.0;
    double minLat = latencies[0];
    double maxLat = latencies[0];
    
    for (double lat : latencies) {
        sum += lat;
        minLat = std::min(minLat, lat);
        maxLat = std::max(maxLat, lat);
    }
    
    result.avgLatencyUs = sum / latencies.size();
    result.minLatencyUs = minLat;
    result.maxLatencyUs = maxLat;
    
    // Standard deviation
    double variance = 0.0;
    for (double lat : latencies) {
        variance += (lat - result.avgLatencyUs) * (lat - result.avgLatencyUs);
    }
    result.stdDevUs = std::sqrt(variance / latencies.size());
    
    // Throughput: tokens per second
    // 16 tokens verified per iteration
    result.throughputTokensPerSec = (16.0 * config.iterations) / (result.totalTimeMs / 1000.0);
    
    delete kernel;
    return result;
}

// ============================================================================
// JSON Output
// ============================================================================

void OutputJSON(const BenchmarkResult& result, const CPUInfo& cpu, 
                const BenchmarkConfig& config, const std::string& filename) {
    Json::Value root;
    
    // Metadata
    root["benchmark"]["name"] = "Tree Attention Kernel";
    root["benchmark"]["version"] = "1.0";
    root["benchmark"]["date"] = "2026-07-19";
    root["benchmark"]["iterations"] = static_cast<Json::UInt64>(config.iterations);
    
    // Hardware
    root["hardware"]["cpu"]["vendor"] = cpu.vendor;
    root["hardware"]["cpu"]["model"] = cpu.model;
    root["hardware"]["cpu"]["cores"] = cpu.cores;
    root["hardware"]["cpu"]["threads"] = cpu.threads;
    root["hardware"]["cpu"]["avx512"] = cpu.hasAVX512;
    root["hardware"]["cpu"]["avx2"] = cpu.hasAVX2;
    root["hardware"]["cache"]["l1_kb"] = cpu.cacheL1;
    root["hardware"]["cache"]["l2_kb"] = cpu.cacheL2;
    root["hardware"]["cache"]["l3_kb"] = cpu.cacheL3;
    
    // Configuration
    root["config"]["head_dim"] = config.headDim;
    root["config"]["num_heads"] = config.numHeads;
    root["config"]["use_avx512"] = config.useAVX512;
    
    // Results
    root["results"]["avg_latency_us"] = result.avgLatencyUs;
    root["results"]["min_latency_us"] = result.minLatencyUs;
    root["results"]["max_latency_us"] = result.maxLatencyUs;
    root["results"]["std_dev_us"] = result.stdDevUs;
    root["results"]["throughput_tokens_per_sec"] = result.throughputTokensPerSec;
    root["results"]["total_time_ms"] = result.totalTimeMs;
    
    // Write to file
    std::ofstream file(filename);
    if (file.is_open()) {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "  ";
        std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
        writer->write(root, &file);
        file.close();
        std::cout << "Results written to: " << filename << "\n";
    }
}

// ============================================================================
// Console Output
// ============================================================================

void OutputConsole(const BenchmarkResult& result, const CPUInfo& cpu) {
    std::cout << "\n========================================\n";
    std::cout << "Tree Attention Benchmark Results\n";
    std::cout << "========================================\n\n";
    
    std::cout << "Hardware:\n";
    std::cout << "  CPU: " << cpu.model << "\n";
    std::cout << "  Cores: " << cpu.cores << "\n";
    std::cout << "  AVX-512: " << (cpu.hasAVX512 ? "Yes" : "No") << "\n";
    std::cout << "\n";
    
    std::cout << "Performance:\n";
    std::cout << "  Average Latency: " << result.avgLatencyUs << " us\n";
    std::cout << "  Min Latency: " << result.minLatencyUs << " us\n";
    std::cout << "  Max Latency: " << result.maxLatencyUs << " us\n";
    std::cout << "  Std Dev: " << result.stdDevUs << " us\n";
    std::cout << "\n";
    std::cout << "  Throughput: " << result.throughputTokensPerSec << " tokens/sec\n";
    std::cout << "  Total Time: " << result.totalTimeMs << " ms\n";
    std::cout << "\n";
    
    // Performance assessment
    std::cout << "Assessment:\n";
    if (result.avgLatencyUs < 500.0) {
        std::cout << "  ✅ EXCELLENT: Sub-microsecond tree verification\n";
    } else if (result.avgLatencyUs < 1000.0) {
        std::cout << "  ✅ GOOD: Under 1ms tree verification\n";
    } else if (result.avgLatencyUs < 2000.0) {
        std::cout << "  ⚠️  ACCEPTABLE: Under 2ms tree verification\n";
    } else {
        std::cout << "  ❌ NEEDS OPTIMIZATION: Over 2ms tree verification\n";
    }
    
    // Throughput assessment
    double tokensPerStep = 16.0 * (1000000.0 / result.avgLatencyUs);  // 16 tokens per tree
    double tps = tokensPerStep;
    std::cout << "  Projected TPS: " << tps << "\n";
    
    if (tps >= 2000.0) {
        std::cout << "  ✅ TARGET MET: 2,000+ TPS achieved\n";
    } else if (tps >= 1500.0) {
        std::cout << "  ⚠️  CLOSE: 1,500+ TPS (target: 2,000)\n";
    } else {
        std::cout << "  ❌ BELOW TARGET: " << tps << " TPS (target: 2,000)\n";
    }
    
    std::cout << "\n========================================\n";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "RawrXD Tree Attention Benchmark\n";
    std::cout << "VAL-032: Speculative Decoding Performance Validation\n";
    std::cout << "========================================\n\n";
    
    BenchmarkConfig config;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--iterations" && i + 1 < argc) {
            config.iterations = std::stoi(argv[++i]);
        } else if (arg == "--head-dim" && i + 1 < argc) {
            config.headDim = std::stoi(argv[++i]);
        } else if (arg == "--no-avx512") {
            config.useAVX512 = false;
        } else if (arg == "--output" && i + 1 < argc) {
            config.outputFile = argv[++i];
        }
    }
    
    // Detect hardware
    CPUInfo cpu = DetectCPU();
    
    std::cout << "Configuration:\n";
    std::cout << "  Iterations: " << config.iterations << "\n";
    std::cout << "  Head Dim: " << config.headDim << "\n";
    std::cout << "  Use AVX-512: " << (config.useAVX512 ? "Yes" : "No") << "\n";
    std::cout << "\n";
    
    // Run benchmark
    BenchmarkResult result = RunBenchmark(config);
    
    // Output results
    OutputConsole(result, cpu);
    
    if (config.outputJSON) {
        OutputJSON(result, cpu, config, config.outputFile);
    }
    
    return 0;
}
