/**
 * Phase 20: Standalone Benchmark Harness
 * 
 * This is a minimal, standalone benchmark that links directly to the MASM
 * kernel object files, bypassing the complex CMake build system and integration
 * debt (JSON paths, LoRAContext size mismatches, etc.).
 * 
 * Goal: Establish P95 latency baseline for ApplyLoRA kernel FMA throughput.
 * Target: <42M cycles (10ms @ 4.2GHz) for 1M element workload.
 */

#include <iostream>
#include <vector>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <intrin.h>
#include <windows.h>

// Reuse our TSCMonitor from Phase 19 E2E harness
#include "../src/tests/TSCMonitor.h"

using namespace RawrXD::E2E;

// External MASM kernel symbols
extern "C" {
    // Optimized version with loop unrolling and prefetching
    void ApplyLoRA_Optimized(float* output, const float* input, int64_t dim);
    
    // Baseline version for comparison
    void ApplyLoRA_Baseline(float* output, const float* input, int64_t dim);
}

// Mock LoRA context beacon (normally set by LoRAContext.cpp)
extern "C" void* g_loraContextBeacon = nullptr;

// LoRA context structure (must match LoRAContext.h and ASM offsets)
#pragma pack(push, 1)
struct LoRAContext {
    float alpha;           // +0
    int32_t rank;          // +4
    int32_t input_dim;     // +8
    uint32_t flags;        // +12
    float* matrix_a;       // +16
    float* matrix_b;       // +24
    uint64_t active;       // +32
};
#pragma pack(pop)

// Constants matching ASM
constexpr uint32_t LORA_FLAG_READY  = 0x00000001;
constexpr uint32_t LORA_FLAG_AVX512 = 0x00000002;
constexpr uint32_t LORA_FLAG_FMA3   = 0x00000004;
constexpr uint32_t LORA_FLAG_VALID  = 0x80000000;

// Benchmark configuration
struct BenchmarkConfig {
    size_t test_size = 1024 * 1024;  // 1M elements (representative)
    int rank = 8;                     // LoRA rank
    int warmup_iterations = 100;      // Warm-up passes
    int benchmark_iterations = 1000;  // Measurement passes
    double target_cycles = 42000000.0; // 42M cycles = 10ms @ 4.2GHz
};

// Results structure
struct BenchmarkResults {
    double min_cycles;
    double max_cycles;
    double avg_cycles;
    double p50_cycles;
    double p95_cycles;
    double p99_cycles;
    double std_dev;
    double throughput_gflops;
    bool passed_budget;
};

// Initialize LoRA context with test data
void InitializeLoRAContext(LoRAContext& ctx, size_t dim, int rank, 
                           std::vector<float>& matrix_a,
                           std::vector<float>& matrix_b) {
    ctx.alpha = 16.0f;
    ctx.rank = rank;
    ctx.input_dim = static_cast<int32_t>(dim);
    ctx.flags = LORA_FLAG_READY | LORA_FLAG_AVX512 | LORA_FLAG_FMA3 | LORA_FLAG_VALID;
    ctx.active = 1;
    
    // A is (rank x dim), B is (dim x rank)
    matrix_a.resize(rank * dim);
    matrix_b.resize(dim * rank);
    
    // Initialize with deterministic values
    for (size_t i = 0; i < matrix_a.size(); ++i) {
        matrix_a[i] = static_cast<float>(i % 100) / 100.0f * 0.1f;
    }
    for (size_t i = 0; i < matrix_b.size(); ++i) {
        matrix_b[i] = static_cast<float>(i % 100) / 100.0f * 0.1f;
    }
    
    ctx.matrix_a = matrix_a.data();
    ctx.matrix_b = matrix_b.data();
}

// Calculate statistics
BenchmarkResults CalculateResults(const std::vector<uint64_t>& samples, 
                                   const BenchmarkConfig& config) {
    BenchmarkResults results;
    
    if (samples.empty()) {
        return results;
    }
    
    std::vector<double> cycles;
    cycles.reserve(samples.size());
    for (auto s : samples) {
        cycles.push_back(static_cast<double>(s));
    }
    
    std::sort(cycles.begin(), cycles.end());
    
    results.min_cycles = cycles.front();
    results.max_cycles = cycles.back();
    results.avg_cycles = std::accumulate(cycles.begin(), cycles.end(), 0.0) / cycles.size();
    
    // Percentiles
    auto percentile = [&](double p) -> double {
        size_t idx = static_cast<size_t>(p / 100.0 * (cycles.size() - 1));
        return cycles[idx];
    };
    
    results.p50_cycles = percentile(50.0);
    results.p95_cycles = percentile(95.0);
    results.p99_cycles = percentile(99.0);
    
    // Standard deviation
    double variance = 0.0;
    for (double c : cycles) {
        variance += (c - results.avg_cycles) * (c - results.avg_cycles);
    }
    variance /= cycles.size();
    results.std_dev = std::sqrt(variance);
    
    // Throughput estimation (approximate FLOPs)
    // LoRA: h = W0x + alpha * (B * A * x)
    // A*x: rank * dim multiplies
    // B*(Ax): dim * rank multiplies
    // Total: 2 * rank * dim FMAs per element
    double flops_per_call = 2.0 * config.rank * config.test_size;
    double seconds = results.avg_cycles / 4.2e9; // Assuming 4.2GHz
    results.throughput_gflops = (flops_per_call / seconds) / 1e9;
    
    results.passed_budget = results.p95_cycles < config.target_cycles;
    
    return results;
}

// Run benchmark for a specific kernel variant
template<typename KernelFunc>
BenchmarkResults RunBenchmark(KernelFunc kernel, const BenchmarkConfig& config,
                               float* output, const float* input, int64_t dim) {
    std::vector<uint64_t> samples;
    samples.reserve(config.benchmark_iterations);
    
    // Warm-up
    for (int i = 0; i < config.warmup_iterations; ++i) {
        kernel(output, input, dim);
        _mm_sfence();
    }
    
    // Benchmark
    for (int i = 0; i < config.benchmark_iterations; ++i) {
        uint64_t start = __rdtsc();
        kernel(output, input, dim);
        uint64_t end = __rdtsc();
        _mm_sfence();
        samples.push_back(end - start);
    }
    
    return CalculateResults(samples, config);
}

// Print results
void PrintResults(const std::string& name, const BenchmarkResults& results,
                  const BenchmarkConfig& config) {
    std::cout << "\n========================================\n";
    std::cout << "  " << name << " Results\n";
    std::cout << "========================================\n";
    std::cout << "Workload: " << (config.test_size / (1024.0 * 1024.0)) << "M elements, rank=" << config.rank << "\n";
    std::cout << "----------------------------------------\n";
    std::cout << "Latency (cycles):\n";
    std::cout << "  Min:  " << results.min_cycles / 1e6 << " M\n";
    std::cout << "  Avg:  " << results.avg_cycles / 1e6 << " M\n";
    std::cout << "  P50:  " << results.p50_cycles / 1e6 << " M\n";
    std::cout << "  P95:  " << results.p95_cycles / 1e6 << " M\n";
    std::cout << "  P99:  " << results.p99_cycles / 1e6 << " M\n";
    std::cout << "  Max:  " << results.max_cycles / 1e6 << " M\n";
    std::cout << "  Std:  " << results.std_dev / 1e6 << " M\n";
    std::cout << "----------------------------------------\n";
    std::cout << "Throughput: " << results.throughput_gflops << " GFLOPS\n";
    std::cout << "----------------------------------------\n";
    std::cout << "Budget Target: " << config.target_cycles / 1e6 << " M cycles\n";
    std::cout << "Status: " << (results.passed_budget ? "PASS ✓" : "FAIL ✗") << "\n";
    
    if (!results.passed_budget) {
        double overshoot = ((results.p95_cycles / config.target_cycles) - 1.0) * 100.0;
        std::cout << "Overshoot: +" << overshoot << "%\n";
    }
    std::cout << "========================================\n";
}

int main(int argc, char* argv[]) {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     RawrXD Phase 20: LoRA Kernel Performance Benchmark       ║\n";
    std::cout << "║     Standalone Harness - Bypassing Integration Debt          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    
    // Parse command line
    BenchmarkConfig config;
    if (argc > 1) {
        config.test_size = static_cast<size_t>(std::atoll(argv[1]));
    }
    if (argc > 2) {
        config.rank = std::atoi(argv[2]);
    }
    
    std::cout << "\nConfiguration:\n";
    std::cout << "  Test size: " << config.test_size << " elements\n";
    std::cout << "  LoRA rank: " << config.rank << "\n";
    std::cout << "  Warmup iterations: " << config.warmup_iterations << "\n";
    std::cout << "  Benchmark iterations: " << config.benchmark_iterations << "\n";
    std::cout << "  Target P95: " << config.target_cycles / 1e6 << " M cycles\n\n";
    
    // Allocate aligned memory for AVX-512
    size_t alloc_size = config.test_size * sizeof(float);
    
    float* input = reinterpret_cast<float*>(_aligned_malloc(alloc_size, 64));
    float* output = reinterpret_cast<float*>(_aligned_malloc(alloc_size, 64));
    
    if (!input || !output) {
        std::cerr << "Failed to allocate aligned memory\n";
        return 1;
    }
    
    // Initialize input data
    for (size_t i = 0; i < config.test_size; ++i) {
        input[i] = 1.0f;
        output[i] = 0.0f;
    }
    
    // Set up LoRA context
    LoRAContext ctx;
    std::vector<float> matrix_a, matrix_b;
    InitializeLoRAContext(ctx, config.test_size, config.rank, matrix_a, matrix_b);
    g_loraContextBeacon = &ctx;
    
    // Verify CPU features
    std::cout << "CPU Features:\n";
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    bool hasAVX512 = (cpuInfo[1] & (1 << 16)) != 0;  // AVX-512F in EBX bit 16
    bool hasFMA = (cpuInfo[2] & (1 << 12)) != 0;     // FMA in ECX bit 12
    std::cout << "  AVX-512: " << (hasAVX512 ? "Yes" : "No") << "\n";
    std::cout << "  FMA3: " << (hasFMA ? "Yes" : "No") << "\n\n";
    
    if (!hasAVX512) {
        std::cout << "WARNING: AVX-512 not detected. Performance will be degraded.\n\n";
    }
    
    // Run benchmarks
    int exit_code = 0;
    
    // Baseline benchmark
    std::cout << "Running BASELINE benchmark...\n";
    auto baseline_results = RunBenchmark(ApplyLoRA_Baseline, config, output, input, 
                                         static_cast<int64_t>(config.test_size));
    PrintResults("ApplyLoRA BASELINE", baseline_results, config);
    
    // Optimized benchmark
    std::cout << "\nRunning OPTIMIZED benchmark...\n";
    auto optimized_results = RunBenchmark(ApplyLoRA_Optimized, config, output, input,
                                            static_cast<int64_t>(config.test_size));
    PrintResults("ApplyLoRA OPTIMIZED", optimized_results, config);
    
    // Speedup calculation
    double speedup = baseline_results.p95_cycles / optimized_results.p95_cycles;
    std::cout << "\n========================================\n";
    std::cout << "  SPEEDUP: " << speedup << "x\n";
    std::cout << "========================================\n";
    
    // TSCMonitor integration - verify our E2E harness works
    std::cout << "\nTSCMonitor Integration Check:\n";
    TSCMonitor::Reset();
    {
        TSCMonitor::Scope scope;
        ApplyLoRA_Optimized(output, input, static_cast<int64_t>(config.test_size));
    }
    auto report = TSCMonitor::GetReport();
    std::cout << "  TSCMonitor P95: " << report.ms << " ms\n";
    std::cout << "  Budget utilization: " << (TSCMonitor::GetBudgetUtilization() * 100.0) << "%\n";
    
    // Cleanup
    _aligned_free(input);
    _aligned_free(output);
    
    // Final verdict
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    if (optimized_results.passed_budget) {
        std::cout << "║  PHASE 20: PASS - Kernel meets P95 latency budget            ║\n";
    } else {
        std::cout << "║  PHASE 20: FAIL - Kernel exceeds P95 latency budget          ║\n";
        exit_code = 1;
    }
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    return exit_code;
}
